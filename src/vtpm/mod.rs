/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 IBM
 *
 * Authors: Vikram Narayanan <>
 *
 */

pub mod init;
// pub mod manufacture;
// pub mod report;

mod bindings;

pub use crate::vtpm::init::{vtpm_init, handle_tpm2_crb_request};
