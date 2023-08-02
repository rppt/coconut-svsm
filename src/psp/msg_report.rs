/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2023 IBM
 *
 * Authors:
 *   Claudio Carvalho <cclaudio@linux.ibm.com>
 */

extern crate alloc;

use crate::getter_func;
use crate::protocols::errors::SvsmReqError;

use alloc::vec::Vec;

/// 64
pub const USER_DATA_SIZE: usize = 64;

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct SnpReportRequest {
    user_data: [u8; USER_DATA_SIZE],
    vmpl: u32,
    rsvd: [u8; 28usize],
}

impl SnpReportRequest {
    pub fn new(vmpl_level: u32) -> Self {
        Self {
            user_data: [0u8; USER_DATA_SIZE],
            vmpl: vmpl_level,
            rsvd: [0u8; 28],
        }
    }

    pub fn set_user_data(&mut self, data: &[u8; USER_DATA_SIZE]) {
        self.user_data.copy_from_slice(data);
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SnpReportResponse {
    status: u32,
    report_size: u32,
    _reserved: [u8; 24],
    report: AttestationReport,
}

impl SnpReportResponse {
    getter_func!(status, u32);
    getter_func!(report_size, u32);
    getter_func!(report, AttestationReport);

    pub fn validate(&self) -> Result<(), SvsmReqError> {
        let e: SvsmReqError = SvsmReqError::invalid_request();

        if self.status != 0 {
            return Err(e);
        }
        if self.report_size != core::mem::size_of::<AttestationReport>() as u32 {
            return Err(e);
        }

        Ok(())
    }
}

impl TryFrom<Vec<u8>> for SnpReportResponse {
    type Error = SvsmReqError;

    fn try_from(payload: Vec<u8>) -> Result<Self, Self::Error> {
        if payload.len() != core::mem::size_of::<SnpReportResponse>() {
            return Err(SvsmReqError::invalid_format());
        }
        let (head, body, _tail) = unsafe { payload.align_to::<SnpReportResponse>() };
        if !head.is_empty() {
            return Err(SvsmReqError::invalid_format());
        }
        let response: SnpReportResponse = body[0];

        Ok(response)
    }
}

// Converted tcb_version from enum to
// struct to make alignment simple.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct TcbVersion {
    raw: u64,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct Signature {
    r: [u8; 72usize],
    s: [u8; 72usize],
    reserved: [u8; 368usize],
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct AttestationReport {
    version: u32,
    guest_svn: u32,
    policy: u64,
    family_id: [u8; 16usize],
    image_id: [u8; 16usize],
    vmpl: u32,
    signature_algo: u32,
    platform_version: TcbVersion,
    platform_info: u64,
    flags: u32,
    reserved0: u32,
    report_data: [u8; 64usize],
    measurement: [u8; 48usize],
    host_data: [u8; 32usize],
    id_key_digest: [u8; 48usize],
    author_key_digest: [u8; 48usize],
    report_id: [u8; 32usize],
    report_id_ma: [u8; 32usize],
    reported_tcb: TcbVersion,
    reserved1: [u8; 24usize],
    chip_id: [u8; 64usize],
    reserved2: [u8; 192usize],
    signature: Signature,
}

impl AttestationReport {
    getter_func!(vmpl, u32);
    getter_func!(report_data, [u8; USER_DATA_SIZE]);
    getter_func!(report_id, [u8; 32]);
}
