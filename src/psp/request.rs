/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2023 IBM
 *
 * Authors:
 *   Claudio Carvalho <cclaudio@linux.ibm.com>
 */

extern crate alloc;

use crate::address::{Address, VirtAddr};
use crate::locking::{LockGuard, SpinLock};
use crate::protocols::errors::SvsmReqError;
use crate::psp::guest_request_cmd::SnpGuestRequestCmd;
use crate::psp::guest_request_msg::SNP_MSG_REPORT_REQ;
use crate::psp::msg_report::{SnpReportRequest, SnpReportResponse, USER_DATA_SIZE};
use crate::types::PAGE_SIZE;

use alloc::vec::Vec;
use log;

use crate::mm::alloc::{allocate_pages, free_page, get_order};

/// SNP_GUEST_REQUEST Object
static GUEST_REQUEST_CMD: SpinLock<SnpGuestRequestCmd> = SpinLock::new(SnpGuestRequestCmd::new());

pub fn snp_guest_request_init() {
    if GUEST_REQUEST_CMD.lock().init().is_err() {
        // All subsequent SNP Guest Request will fail
        log::error!("Failed to initialize SNP_GUEST_REQUEST\n");
    }
}

/// Request a vmpl0 attestation report to the AMD secure processor (PSP).
///
/// @user_data: data that will be included in the attestation report and signed
///
/// It returns the SnpReportResponse if success, otherwise an error code.
///
/// Further information can be found in the Secure Nested Paging Firmware ABI
/// Specification, Chapter 7, subsection Attestation
pub fn get_report(user_data: &[u8; USER_DATA_SIZE]) -> Result<SnpReportResponse, SvsmReqError> {
    let mut cmd: LockGuard<SnpGuestRequestCmd> = GUEST_REQUEST_CMD.lock();

    // Instantiate a vmpl0 report request
    let mut req = SnpReportRequest::new(0);
    req.set_user_data(user_data);

    const REPORT_REQUEST_SIZE: usize = core::mem::size_of::<SnpReportRequest>();

    // The SnpReportRequest structure size has to fit in the
    // SnpGuestRequestMsgHdr.msg_size field, which is a u16.
    assert!(u16::try_from(REPORT_REQUEST_SIZE).is_ok());

    let payload_size = REPORT_REQUEST_SIZE as u16;
    let payload = VirtAddr::from(&req as *const _ as *const u8);

    let message: Vec<u8> = cmd.send_request(SNP_MSG_REPORT_REQ, false, payload, payload_size)?;

    let response = SnpReportResponse::try_from(message)?;
    response.validate()?;

    Ok(response)
}

/// Request a vmpl0 extended attestation report to the AMD secure processor (PSP)
///
/// @user_data:    data that will be included in the attestation report and signed
///
/// @certs_buffer: Buffer to store the certificate chain needed to verify
///                the attestation report. Make sure to load the certificates from
///                from the host using the sev-guest tools.
///
/// @certs_buffer_size: size of the certs_buffer
///
/// The following error is returned if certs_buffer is too small; the certs_buffer_size
/// returned in the error is the minimum buffer size required.
///
/// SvsmReqError::FatalError(SvsmError::Ghcb(GhcbError::VmgexitError(certs_buffer_size, psp_rc)))
///
pub fn get_ext_report(
    user_data: &[u8; USER_DATA_SIZE],
    certs_buffer: VirtAddr,
    certs_buffer_size: usize,
) -> Result<SnpReportResponse, SvsmReqError> {
    if certs_buffer.is_null() || certs_buffer_size == 0 {
        return Err(SvsmReqError::invalid_parameter());
    }

    let mut cmd: LockGuard<SnpGuestRequestCmd> = GUEST_REQUEST_CMD.lock();

    cmd.ext_data().set_len(certs_buffer_size)?;
    cmd.ext_data().clear(certs_buffer_size);

    // Instantiate a vmpl0 report request
    let mut req = SnpReportRequest::new(0);
    req.set_user_data(user_data);

    const REPORT_REQUEST_SIZE: usize = core::mem::size_of::<SnpReportRequest>();

    // The SnpReportRequest structure size has to fit in the
    // SnpGuestRequestMsgHdr.msg_size field, which is a u16.
    assert!(u16::try_from(REPORT_REQUEST_SIZE).is_ok());

    let payload_size = REPORT_REQUEST_SIZE as u16;
    let payload = VirtAddr::from(&req as *const _ as *const u8);

    let message: Vec<u8> = cmd.send_request(SNP_MSG_REPORT_REQ, true, payload, payload_size)?;

    let response = SnpReportResponse::try_from(message)?;
    response.validate()?;

    // The sev-guest tools, in the host, are used to load the certificates needed to
    // verify the attestation report. If they were not loaded (yet), print a warning.
    if cmd.ext_data().is_clear(certs_buffer_size) {
        log::warn!("Attestation report certificates not found.");
    } else {
        cmd.ext_data().copy_to(certs_buffer, certs_buffer_size);
    }

    Ok(response)
}

#[cfg(test)]
mod tests {
    use crate::psp::msg_report::SnpReportRequest;

    #[test]
    fn u16_from_report_request_size() {
        const REPORT_REQUEST_SIZE: usize = core::mem::size_of::<SnpReportRequest>();
        // In SnpGuestRequestMsgHdr, the size of SnpReportRequest has to fit in a u16
        assert!(u16::try_from(REPORT_REQUEST_SIZE).is_ok());
    }
}
