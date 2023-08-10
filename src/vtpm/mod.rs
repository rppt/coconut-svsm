/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 IBM
 *
 * Authors: Vikram Narayanan <>
 *
 */

pub mod init;
pub mod ms_tpm;

mod bindings;
mod wrapper;

pub use crate::vtpm::init::vtpm_init;
