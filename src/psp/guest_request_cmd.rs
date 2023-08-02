/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2023 IBM
 *
 * Authors: Claudio Carvalho <cclaudio@linux.ibm.com>
 */

extern crate alloc;

use crate::address::VirtAddr;
use crate::cpu::percpu::this_cpu_mut;
use crate::error::SvsmError;
use crate::protocols::errors::SvsmReqError;
use crate::psp::guest_request_msg::{SnpGuestRequestExtData, SnpGuestRequestMsg};
use crate::sev::ghcb::GhcbError;
use crate::sev::secrets_page::{disable_vmpck0, get_vmpck0, is_vmpck0_clear, VMPCK_SIZE};
use crate::{getter_func, BIT};

use alloc::vec::Vec;

///
/// Hypervisor error codes
///

/// BIT!(32)
pub const SNP_GUEST_REQ_INVALID_LEN: u64 = BIT!(32);
/// BIT!(33)
pub const SNP_GUEST_REQ_ERR_BUSY: u64 = BIT!(33);

#[derive(Debug)]
pub struct SnpGuestRequestCmd {
    // SNP_GUEST_REQUEST requires two pages: one for
    // the request and another for the response message. Both
    // of them have to be assigned to the hypervisor (shared).
    request: SnpGuestRequestMsg,
    response: SnpGuestRequestMsg,

    // SNP Extended Guest Request. Its pages are also shared
    // with the hypervisor
    ext_data: SnpGuestRequestExtData,

    msg_seqno: u64,

    is_initialized: bool,
}

impl SnpGuestRequestCmd {
    getter_func!(ext_data, SnpGuestRequestExtData);

    pub const fn new() -> Self {
        Self {
            request: SnpGuestRequestMsg::new(),
            response: SnpGuestRequestMsg::new(),
            ext_data: SnpGuestRequestExtData::new(),
            msg_seqno: 0,
            is_initialized: false,
        }
    }

    pub fn init(&mut self) -> Result<(), SvsmReqError> {
        if !self.is_initialized {
            self.request.alloc()?;
            self.response.alloc()?;
            self.ext_data.alloc()?;

            // The SNP ABI spec says the request, response and data pages have
            // to be shared with the hypervisor
            self.request.set_shared()?;
            self.response.set_shared()?;
            self.ext_data.set_shared()?;

            self.is_initialized = true;
        }

        Ok(())
    }

    fn seqno_last_used(&self) -> u64 {
        self.msg_seqno
    }

    fn seqno_add_two(&mut self) {
        self.msg_seqno += 2;
    }

    /// Call the GHCB layer to send the encrypted SNP_GUEST_REQUEST message
    /// to the AMD Secure Processor (PSP).
    fn send(&mut self, extended: bool) -> Result<(), SvsmReqError> {
        self.response.clear();

        if extended {
            this_cpu_mut().ghcb().guest_ext_request(
                self.request.as_va(),
                self.response.as_va(),
                self.ext_data.as_va(),
                self.ext_data.npages(),
            )?;
        } else {
            this_cpu_mut()
                .ghcb()
                .guest_request(self.request.as_va(), self.response.as_va())?;
        }

        // The PSP firmware increases the sequence number only when
        // it receives a request successfully. Hence, we sync our
        // sequence number (add two) only when we receive a response
        // successfully.
        self.seqno_add_two();

        Ok(())
    }

    /// Send a SNP_GUEST_REQUEST message to the AMD Secure processor (PSP) following
    /// the GHCB protocol. Messages are a encrypted/decrypted using AES_GCM. Each
    /// message has sequence number, which is monotonic.
    ///
    /// @msg_type = SNP_GUEST_REQUEST type stored in the payload
    /// @extended = whether or not it is an extended SNP Guest Request
    /// @payload  = VirtAddr of the request, which will be encrypted
    /// @payload_size = size of the payload
    pub fn send_request(
        &mut self,
        msg_type: u8,
        extended: bool,
        payload: VirtAddr,
        payload_size: u16,
    ) -> Result<Vec<u8>, SvsmReqError> {
        if !self.is_initialized {
            return Err(SvsmReqError::invalid_request());
        }
        if is_vmpck0_clear() {
            return Err(SvsmReqError::invalid_request());
        }

        let Some(msg_seqno) = self.seqno_last_used().checked_add(1) else {
            log::error!("Encryption: sequence number overflow");
            return Err(SvsmReqError::invalid_request());
        };

        let vmpck0: [u8; VMPCK_SIZE] = get_vmpck0();

        self.request
            .encrypt_save(msg_type, msg_seqno, &vmpck0, payload, payload_size)?;

        if let Err(e) = self.send(extended) {
            if let SvsmReqError::FatalError(SvsmError::Ghcb(GhcbError::VmgexitError(_rbx, info2))) =
                e
            {
                //
                // For some reason the hypervisor did not forward the request; we need to handle
                // the error and prevent the IV from being reused
                //
                match info2 & 0xffff_ffff_0000_0000u64 {
                    // The certs_buf is too small. The required buffer size is embedded in the
                    // Error, i.e. rbx.
                    SNP_GUEST_REQ_INVALID_LEN => {
                        if extended {
                            if let Err(e1) = self.send(false) {
                                log::warn!(
                                    "SNP_GUEST_REQ_INVALID_LEN. Aborting, IV could be reused"
                                );
                                disable_vmpck0();
                                return Err(e1);
                            }
                            return Err(e);
                        }
                    }
                    // Hypervisor is busy.
                    SNP_GUEST_REQ_ERR_BUSY => {
                        if let Err(e2) = self.send(false) {
                            log::warn!("SNP_GUEST_REQ_ERR_BUSY. Aborting, IV could be reused");
                            disable_vmpck0();
                            return Err(e2);
                        }
                        // ... continue, we resent the request and it worked.
                    }
                    // Failed for unknown reason. Status codes can be found in
                    // the SEV SNP ABI spec or in the linux kernel include/uapi/linux/psp-sev.h
                    _ => {
                        log::error!("SNP_GUEST_REQUEST failed, unknown error code={}\n", info2);
                        disable_vmpck0();
                        return Err(e);
                    }
                }
            }
        }

        let msg_seqno = self.seqno_last_used();

        match self.response.decrypt_get(msg_type + 1, msg_seqno, &vmpck0) {
            Ok(resp) => Ok(resp),
            Err(e) => {
                disable_vmpck0();
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use core::ptr::copy_nonoverlapping;

    use crate::{
        address::VirtAddr,
        psp::guest_request_msg::{SnpGuestRequestExtData, SnpGuestRequestMsg, SNP_MSG_REPORT_REQ},
        sev::secrets_page::VMPCK_SIZE,
        types::PAGE_SIZE,
    };

    use crate::psp::guest_request_cmd::SnpGuestRequestCmd;

    static mut REQUEST: [u8; PAGE_SIZE] = [0u8; PAGE_SIZE];
    static mut RESPONSE: [u8; PAGE_SIZE] = [0u8; PAGE_SIZE];

    fn init_guest_request_cmd(cmd: &mut SnpGuestRequestCmd) {
        let req_va = unsafe { VirtAddr::from(REQUEST.as_mut_ptr()) };
        let resp_va = unsafe { VirtAddr::from(RESPONSE.as_mut_ptr()) };

        cmd.msg_seqno = 1;
        cmd.request = SnpGuestRequestMsg { buffer: req_va };
        cmd.response = SnpGuestRequestMsg { buffer: resp_va };
        cmd.ext_data = SnpGuestRequestExtData::new();
        cmd.is_initialized = true;
    }

    #[test]
    fn aes_gcm_encrypt_and_decrypt() {
        let mut cmd = SnpGuestRequestCmd::new();
        init_guest_request_cmd(&mut cmd);

        let plaintext = b"message-to-be-encrypted";
        let vmpck0 = [5u8; VMPCK_SIZE];

        let result = cmd.request.encrypt_save(
            SNP_MSG_REPORT_REQ,
            cmd.msg_seqno,
            &vmpck0,
            VirtAddr::from(plaintext as *const u8),
            plaintext.len() as u16,
        );
        assert!(result.is_ok());

        unsafe {
            copy_nonoverlapping(
                cmd.request.as_va().as_ptr::<u8>(),
                cmd.response.as_va().as_mut_ptr::<u8>(),
                PAGE_SIZE,
            );
        }

        let result = cmd
            .response
            .decrypt_get(SNP_MSG_REPORT_REQ, cmd.msg_seqno, &vmpck0);
        assert!(result.is_ok());

        let decrypted_text = result.unwrap();

        assert_eq!(plaintext, decrypted_text.as_slice());
    }
}
