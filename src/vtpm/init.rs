
/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2023 IBM
 *
 * Authors: Claudio Carvalho <cclaudio@linux.ibm.com>
 */

use crate::vtpm::ms_tpm::vtpm_startup_clear;
use crate::vtpm::bindings::{
    _plat__Signal_Reset, _plat__Signal_PowerOn,
    TPM_Manufacture, TPM_TearDown, _plat__SetNvAvail,
};

use core::ffi::c_int;

pub fn test_libcrypto_call() {
    use crate::vtpm::bindings::{SHA512_DIGEST_LENGTH, SHA512};
    let mut digest = [0_u8; SHA512_DIGEST_LENGTH as usize];
    let mut text = [0_u8; 64];
    text[0] = 2;
    text[1] = 3;
    text[2] = 4;
    text[3] = 5;
    unsafe {
        SHA512(
            text.as_ptr(),
            text.len(),
            digest.as_mut_ptr(),
        );
    }
    log::info!("digest {:x?}", digest);
}

pub fn vtpm_init() {
    unsafe {
        let mut rc = TPM_TearDown();
        if rc != 0 {
            log::error!("TPM_TearDown failed, rc={}", rc);
            return;
        }
        rc = TPM_Manufacture(1);
        if rc != 0 {
            log::error!("TPM_Manufacture failed, rc={}", rc);
            return;
        }

        // NV is not available by default.
        _plat__SetNvAvail();

        rc = _plat__Signal_PowerOn();
        if rc != 0 {
            log::error!("_plat__Signal_PowerOn failed, rc={}", rc);
            return;
        }
        rc = _plat__Signal_Reset();
        if rc != 0 {
            log::error!("_plat__Signal_Reset failed, rc={}", rc);
            return;
        }
    }
    if let Err(rc) = vtpm_startup_clear() {
        log::error!("vTPM startup failed, rc={}", rc);
        return;
    }
    log::info!("vTPM initialized");
}
