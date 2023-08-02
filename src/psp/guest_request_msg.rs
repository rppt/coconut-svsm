/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2023 IBM
 *
 * Authors: Claudio Carvalho <cclaudio@linux.ibm.com>
 */

extern crate alloc;

use crate::address::{Address, VirtAddr};
use crate::cpu::percpu::this_cpu_mut;
use crate::mm::alloc::{allocate_page, allocate_pages, get_order};
use crate::protocols::errors::SvsmReqError;
use crate::sev::secrets_page::VMPCK_SIZE;
use crate::types::{PAGE_SHIFT, PAGE_SIZE};
use crate::{funcs, getter_func};

use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, Key, KeyInit, Nonce,
};
use alloc::vec::Vec;
use core::cmp::min;
use core::ptr;
use core::ptr::{copy_nonoverlapping, write_bytes};
use core::slice::{from_raw_parts, from_raw_parts_mut};

///
/// AES_GCM
///

/// 1
const SNP_AEAD_AES_256_GCM: u8 = 1;

/// In the SEV-SNP ABI spec, the authentication tag should be at most 128 bits.
/// 16
const AUTHTAG_SIZE: usize = 16;
/// In the SEV-SNP ABI spec, the IV should be at most 96 bits; but the bits
/// not used must be zeroed.
/// 12
const IV_SIZE: usize = 12;

///
/// SnpGuestRequestMsg types
///

/// 0
pub const SNP_MSG_TYPE_INVALID: u8 = 0;
/// 5
pub const SNP_MSG_REPORT_REQ: u8 = 5;
/// 6
pub const SNP_MSG_REPORT_RSP: u8 = 6;

///
/// SnpGuestRequestMsg version
///

/// 1
const HDR_VERSION: u8 = 1;
/// 1
const MSG_VERSION: u8 = 1;

///
/// SnpGuestRequestMsg size
///

/// PAGE_SIZE - MSG_PAYLOAD_SIZE
const MSG_HDR_SIZE: usize = core::mem::size_of::<SnpGuestRequestMsgHdr>();
/// 4000
const MSG_PAYLOAD_SIZE: usize = 4000;
/// 0x4000 (4 pages)
pub const SNP_GUEST_REQ_MAX_DATA_SIZE: usize = 0x4000;

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct SnpGuestRequestMsgHdr {
    authtag: [u8; 32usize],
    msg_seqno: u64,
    rsvd1: [u8; 8usize],
    algo: u8,
    hdr_version: u8,
    hdr_sz: u16,
    msg_type: u8,
    msg_version: u8,
    msg_sz: u16,
    rsvd2: u32,
    msg_vmpck: u8,
    rsvd3: [u8; 35usize],
}

#[allow(dead_code)]
impl SnpGuestRequestMsgHdr {
    getter_func!(authtag, [u8; 32]);
    funcs!(msg_seqno, u64);
    funcs!(algo, u8);
    funcs!(hdr_version, u8);
    funcs!(hdr_sz, u16);
    funcs!(msg_type, u8);
    funcs!(msg_version, u8);
    funcs!(msg_sz, u16);
    funcs!(msg_vmpck, u8);

    pub fn new() -> SnpGuestRequestMsgHdr {
        SnpGuestRequestMsgHdr {
            authtag: [0; 32],
            msg_seqno: 0,
            rsvd1: [0; 8],
            algo: 0,
            hdr_version: 0,
            hdr_sz: 0,
            msg_type: 0,
            msg_version: 0,
            msg_sz: 0,
            rsvd2: 0,
            msg_vmpck: 0,
            rsvd3: [0; 35],
        }
    }

    fn set_authtag_from_slice(&mut self, tag: &[u8]) -> Result<(), SvsmReqError> {
        if tag.len() < AUTHTAG_SIZE {
            return Err(SvsmReqError::invalid_format());
        }
        self.authtag[..AUTHTAG_SIZE].copy_from_slice(&tag[..AUTHTAG_SIZE]);
        Ok(())
    }

    pub fn validate(&self, msg_type: u8, msg_seqno: &u64) -> Result<(), SvsmReqError> {
        let e: SvsmReqError = SvsmReqError::invalid_request();

        let Ok(header_size) = u16::try_from(MSG_HDR_SIZE) else {
            return Err(e);
        };
        if self.hdr_version != HDR_VERSION {
            return Err(e);
        }
        if self.hdr_sz != header_size {
            return Err(e);
        }
        if self.algo != SNP_AEAD_AES_256_GCM {
            return Err(e);
        }
        if self.msg_type != msg_type {
            return Err(e);
        }
        if self.msg_vmpck != 0 {
            return Err(e);
        }
        if self.msg_seqno != *msg_seqno {
            return Err(e);
        }

        Ok(())
    }

    pub fn get_aad_slice(&self) -> &[u8] {
        let msg_base = self as *const _ as *const u8;
        let msg_algo = &self.algo as *const _ as *const u8;

        let algo_offset = unsafe { msg_algo.offset_from(msg_base) } as usize;

        unsafe { from_raw_parts(msg_algo, MSG_HDR_SIZE - algo_offset) }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct SnpGuestRequestMsg {
    /// PAGE_SIZE that carries the actual structure:
    ///
    ///     #[repr(C, packed)]
    ///     struct SnpGuestRequestMsg {
    ///             hdr: SnpGuestRequestMsgHdr,
    ///             payload: [u8; MSG_PAYLOAD_SIZE],
    ///     }
    ///
    pub buffer: VirtAddr,
}

impl SnpGuestRequestMsg {
    pub const fn new() -> Self {
        Self {
            buffer: VirtAddr::null(),
        }
    }

    pub fn alloc(&mut self) -> Result<(), SvsmReqError> {
        self.buffer = allocate_page()?;
        Ok(())
    }

    pub fn set_shared(&self) -> Result<(), SvsmReqError> {
        this_cpu_mut().get_pgtable().set_shared_4k(self.buffer)?;
        Ok(())
    }

    pub fn clear(&mut self) {
        unsafe {
            write_bytes(self.buffer.as_mut_ptr::<u8>(), 0u8, PAGE_SIZE);
        }
    }

    pub fn as_va(&self) -> VirtAddr {
        self.buffer
    }

    pub fn get_hdr_copy(&self) -> SnpGuestRequestMsgHdr {
        let mut msg_hdr = SnpGuestRequestMsgHdr::new();
        unsafe {
            copy_nonoverlapping(
                self.buffer.as_ptr::<u8>(),
                ptr::addr_of_mut!(msg_hdr) as *mut u8,
                MSG_HDR_SIZE,
            );
        }

        msg_hdr
    }

    fn set_hdr(&mut self, msg_hdr: &SnpGuestRequestMsgHdr) {
        unsafe {
            copy_nonoverlapping(
                msg_hdr as *const _ as *const u8,
                self.buffer.as_mut_ptr() as *mut u8,
                MSG_HDR_SIZE,
            );
        }
    }

    fn set_payload(&mut self, payload: *const u8, len: usize) {
        unsafe {
            copy_nonoverlapping(
                payload,
                self.buffer.as_mut_ptr::<u8>().offset(MSG_HDR_SIZE as isize),
                len,
            );
        }
    }

    pub unsafe fn payload_offset(&mut self) -> *mut u8 {
        self.buffer.as_mut_ptr::<u8>().offset(MSG_HDR_SIZE as isize)
    }

    // Encrypt the given plaintext and save the obtained ciphertext in the message payload
    pub fn encrypt_save(
        &mut self,
        msg_type: u8,
        msg_seqno: u64,
        vmpck0: &[u8; VMPCK_SIZE],
        plaintext: VirtAddr,
        plaintext_len: u16,
    ) -> Result<(), SvsmReqError> {
        // Construct message header
        let mut msg_hdr = SnpGuestRequestMsgHdr::new();
        msg_hdr.set_hdr_sz(MSG_HDR_SIZE as u16);
        msg_hdr.set_algo(SNP_AEAD_AES_256_GCM);
        msg_hdr.set_hdr_version(HDR_VERSION);
        msg_hdr.set_msg_sz(plaintext_len);
        msg_hdr.set_msg_type(msg_type);
        msg_hdr.set_msg_version(MSG_VERSION);
        msg_hdr.set_msg_vmpck(0);
        msg_hdr.set_msg_seqno(msg_seqno);

        let aad_slice: &[u8] = msg_hdr.get_aad_slice();
        let plaintext_slice: &[u8] =
            unsafe { from_raw_parts(plaintext.as_ptr() as *const u8, plaintext_len as usize) };
        let payload = Payload {
            msg: plaintext_slice,
            aad: aad_slice,
        };

        let key = Key::<Aes256Gcm>::from_slice(vmpck0);
        let gcm = Aes256Gcm::new(&key);
        let iv: [u8; IV_SIZE] = build_iv(msg_seqno);
        let nonce = Nonce::from_slice(&iv);

        let Ok(buffer) = gcm.encrypt(&nonce, payload) else {
            log::warn!("AES_GCM.encrypt() failed");
            return Err(SvsmReqError::invalid_format());
        };

        // RustCrypto AES_GCM.encrypt() returns a postfix authenticated tag (i.e. ciphertext + tag)
        // Copy the authtag to the message header.
        let ciphertext_len = buffer.len() - AUTHTAG_SIZE;
        let (ciphertext, tag) = buffer.split_at(plaintext_len as usize);
        msg_hdr.set_authtag_from_slice(tag)?;

        self.clear();
        self.set_hdr(&msg_hdr);
        self.set_payload(ciphertext.as_ptr(), ciphertext_len);

        Ok(())
    }

    /// Decrypt the message payload and return the plaintext obtained
    pub fn decrypt_get(
        &mut self,
        msg_type: u8,
        msg_seqno: u64,
        vmpck0: &[u8; VMPCK_SIZE],
    ) -> Result<Vec<u8>, SvsmReqError> {
        let msg_hdr = self.get_hdr_copy();

        msg_hdr.validate(msg_type, &msg_seqno)?;

        // Make sure the message payload have space also for the authenticated tag.
        if msg_hdr.msg_sz() as usize + AUTHTAG_SIZE > MSG_PAYLOAD_SIZE {
            return Err(SvsmReqError::incomplete());
        }

        let aad_slice: &[u8] = msg_hdr.get_aad_slice();
        let payload_slice = unsafe {
            from_raw_parts_mut(
                self.payload_offset(),
                msg_hdr.msg_sz() as usize + AUTHTAG_SIZE,
            )
        };

        // Append the authenticated tag to the message payload.
        // RustCrypto AES_GCM requires postfix authtag.
        let start: usize = usize::from(msg_hdr.msg_sz());
        payload_slice[start..].copy_from_slice(&msg_hdr.authtag()[..AUTHTAG_SIZE]);

        let payload = Payload {
            msg: payload_slice,
            aad: aad_slice,
        };

        let key = Key::<Aes256Gcm>::from_slice(vmpck0);
        let gcm = Aes256Gcm::new(&key);
        let iv: [u8; IV_SIZE] = build_iv(msg_seqno);
        let nonce = Nonce::from_slice(&iv);

        let Ok(buffer) = gcm.decrypt(&nonce, payload) else {
            log::warn!("AES_GCM.decrypt() failed");
            return Err(SvsmReqError::invalid_format());
        };

        Ok(buffer)
    }
}

fn build_iv(msg_seqno: u64) -> [u8; IV_SIZE] {
    const U64_SIZE: usize = core::mem::size_of::<u64>();
    let mut iv: [u8; IV_SIZE] = [0u8; IV_SIZE];

    iv[..U64_SIZE].copy_from_slice(&msg_seqno.to_ne_bytes());
    iv
}

#[derive(Debug, Copy, Clone)]
pub struct SnpGuestRequestExtData {
    buffer: VirtAddr,
    len: usize,
}

impl SnpGuestRequestExtData {
    pub const fn new() -> Self {
        Self {
            buffer: VirtAddr::null(),
            len: 0,
        }
    }

    pub fn alloc(&mut self) -> Result<(), SvsmReqError> {
        self.buffer = allocate_pages(get_order(SNP_GUEST_REQ_MAX_DATA_SIZE))?;
        assert!(self.buffer.is_page_aligned());
        self.len = SNP_GUEST_REQ_MAX_DATA_SIZE;
        Ok(())
    }

    pub fn set_shared(&mut self) -> Result<(), SvsmReqError> {
        let start = usize::from(self.buffer);
        let end = start + self.len;
        for page in (start..end).step_by(PAGE_SIZE) {
            let vpage = VirtAddr::from(page);
            this_cpu_mut().get_pgtable().set_shared_4k(vpage)?;
        }
        Ok(())
    }

    pub fn set_len(&mut self, len: usize) -> Result<(), SvsmReqError> {
        if len < PAGE_SIZE || len > SNP_GUEST_REQ_MAX_DATA_SIZE {
            return Err(SvsmReqError::invalid_parameter());
        }
        Ok(())
    }

    pub fn as_va(&self) -> VirtAddr {
        self.buffer
    }

    pub fn npages(&self) -> u64 {
        (self.len >> PAGE_SHIFT) as u64
    }

    /// Clear len bytes from self.buffer
    pub fn clear(&mut self, len: usize) {
        unsafe {
            write_bytes(
                self.buffer.as_mut_ptr::<u8>(),
                0u8,
                min(len, SNP_GUEST_REQ_MAX_DATA_SIZE),
            );
        }
    }

    pub fn copy_to(&self, buf: VirtAddr, buf_size: usize) {
        unsafe {
            ptr::copy_nonoverlapping(
                self.buffer.as_mut_ptr::<u8>(),
                buf.as_mut_ptr::<u8>(),
                min(buf_size, SNP_GUEST_REQ_MAX_DATA_SIZE as usize),
            );
        }
    }

    /// Check if the first len bytes are zeroed
    pub fn is_clear(&self, len: usize) -> bool {
        let buf = self.buffer.as_ptr() as *const [u8; SNP_GUEST_REQ_MAX_DATA_SIZE];

        let end: usize = min(len, SNP_GUEST_REQ_MAX_DATA_SIZE);
        unsafe { (*buf)[..end].into_iter().all(|e| *e == 0) }
    }
}

#[cfg(test)]
mod tests {
    use crate::psp::guest_request_msg::{SnpGuestRequestMsgHdr, IV_SIZE, MSG_HDR_SIZE};

    #[test]
    fn u16_from_guest_msg_hdr_size() {
        assert!(u16::try_from(MSG_HDR_SIZE).is_ok());
    }

    #[test]
    fn iv_bigger_than_u64_size() {
        const U64_SIZE: usize = core::mem::size_of::<u64>();
        assert!(IV_SIZE >= U64_SIZE);
    }

    #[test]
    fn aad_size() {
        let hdr = SnpGuestRequestMsgHdr::new();
        let aad = hdr.get_aad_slice();

        let hdr_algo_offset: usize = 48;

        assert_eq!(aad.len(), MSG_HDR_SIZE - hdr_algo_offset);
    }
}
