/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2023 IBM
 *
 * Authors: Vikram Narayanan <>
 *
 */

#![allow(non_camel_case_types)]

// use crate::vtpm::bindings::*;
use crate::println;

use crate::vtpm::bindings::strlen;
use crate::vtpm::bindings::Regs;
//use crate::*;
use crate::mm::alloc::ALLOCATOR;

use core::alloc::GlobalAlloc;
use core::alloc::Layout;
use core::slice;
use core::str;

pub type c_char = u8;

const ALIGN_32: usize = 32;

#[no_mangle]
pub extern "C" fn malloc(sz: usize) -> *mut u8 {
    let layout = match Layout::from_size_align(sz, ALIGN_32) {
        Ok(l) => l,
        Err(_e) => panic!("malloc: size is not 32 bytes aligned"),
    };

    let ptr: *mut u8 = unsafe { ALLOCATOR.alloc(layout) };
    ptr
}

#[no_mangle]
pub extern "C" fn realloc(ptr: *mut u8, sz: usize) -> *mut u8 {
    let layout = match Layout::from_size_align(sz, ALIGN_32) {
        Ok(l) => l,
        Err(_e) => panic!("malloc: size is not 32 bytes aligned"),
    };

    let ptr: *mut u8 = unsafe { ALLOCATOR.realloc(ptr, layout, sz) };
    ptr
}

#[no_mangle]
pub extern "C" fn free(ptr: *mut u8) {
    let ptr_size: usize = 64;
    let layout = match Layout::from_size_align(ptr_size, ALIGN_32) {
        Ok(l) => l,
        Err(_e) => panic!("free: ptr_size is not 32 bytes aligned")
    };
    unsafe { ALLOCATOR.dealloc(ptr, layout) }
}

#[no_mangle]
pub extern "C" fn serial_out(s: *const c_char) {
    unsafe {
        let rust_str =
            str::from_utf8_unchecked(slice::from_raw_parts(s, strlen(s as *const i8) as usize));
        println!("{}", rust_str);
    }
}

impl From<(u32, u32, u32, u32)> for Regs {
    fn from(t: (u32, u32, u32, u32)) -> Regs {
        Regs {
            eax: t.0,
            ebx: t.1,
            ecx: t.2,
            edx: t.3,
        }
    }
}
