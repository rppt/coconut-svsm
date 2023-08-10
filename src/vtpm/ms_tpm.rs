
/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2023 IBM
 *
 * Authors: Claudio Carvalho <cclaudio@linux.ibm.com>
 */

extern crate alloc;

use crate::vtpm::bindings::{TPM2_Startup, Startup_In, ExecuteCommand, TPM_RC};

use alloc::vec::Vec;
use core::ptr;

const TPM_RC_SUCCESS: u32 = 0;

pub struct TpmResponse {
    pub data: Vec<u8>,
}

pub fn send_tpm_command(request: &mut [u8]) -> TpmResponse {
    let default_vec_size: usize = 4096;

    let mut __resp_sz: u32 = default_vec_size.try_into().unwrap();
    let mut _resp_sz: *mut u32 = &mut __resp_sz;

    let mut __resp_vec: Vec<u8> = Vec::with_capacity(default_vec_size);
    let mut _resp_vec: *mut u8 = __resp_vec.as_mut_ptr();
    unsafe {
        let resp_vec: *mut *mut u8 = &mut _resp_vec as *mut *mut u8;
//        log::info!("TPM Request: len={:#x} {:02x?}\n", {request.len()}, request);
        ExecuteCommand(
            request.len() as u32,
            request.as_mut_ptr(),
            _resp_sz,
            resp_vec,
        );
        __resp_vec.set_len(__resp_sz as usize);
    }
//    log::info!("TPM Response: len={:#x} {:02x?}\n", __resp_sz, {&__resp_vec});
    let tpm_resp: TpmResponse = TpmResponse {
        data: __resp_vec,
    };
    tpm_resp
}

pub fn vtpm_startup_clear() -> Result<(), u32> {
    const TPM_SU_CLEAR: u16 = 0;

    let mut input = Startup_In { startupType: 0 };
    input.startupType = TPM_SU_CLEAR;

    let rc: TPM_RC = unsafe { TPM2_Startup(ptr::addr_of_mut!(input)) };

    if rc != TPM_RC_SUCCESS {
        return Err(rc);
    }

    Ok(())
}
