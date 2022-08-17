// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

use crate::types::{VirtAddr, SVSM_CS};
use core::arch::{asm, global_asm};
use super::control_regs::read_cr2;
use super::tss::IST_DF;
use crate::util::halt;
use crate::println;
use core::mem;

pub const  _DE_VECTOR : usize = 0;
pub const  _DB_VECTOR : usize = 1;
pub const _NMI_VECTOR : usize = 2;
pub const  _BP_VECTOR : usize = 3;
pub const  _OF_VECTOR : usize = 4;
pub const  _BR_VECTOR : usize = 5;
pub const  _UD_VECTOR : usize = 6;
pub const  _NM_VECTOR : usize = 7;
pub const   DF_VECTOR : usize = 8;
pub const _CSO_VECTOR : usize = 9;
pub const  _TS_VECTOR : usize = 10;
pub const  _NP_VECTOR : usize = 11;
pub const  _SS_VECTOR : usize = 12;
pub const   GP_VECTOR : usize = 13;
pub const   PF_VECTOR : usize = 14;
pub const  _MF_VECTOR : usize = 16;
pub const  _AC_VECTOR : usize = 17;
pub const _MCE_VECTOR : usize = 18;
pub const  _XF_VECTOR : usize = 19;
pub const  _CP_VECTOR : usize = 21;
pub const  _HV_VECTOR : usize = 28;
pub const  _VC_VECTOR : usize = 29;
pub const  _SX_VECTOR : usize = 30;

#[repr(C, packed)]
pub struct x86_regs {
    r15         : usize,
    r14         : usize,
    r13         : usize,
    r12         : usize,
    r11         : usize,
    r10         : usize,
    r9          : usize,
    r8          : usize,
    rbp         : usize,
    rdi         : usize,
    rsi         : usize,
    rdx         : usize,
    rcx         : usize,
    rbx         : usize,
    rax         : usize,
    vector      : usize,
    error_code  : usize,
    rip         : usize,
    cs          : usize,
    flags       : usize,
    rsp         : usize,
    ss          : usize,
}

#[derive(Copy, Clone)]
#[repr(C, packed)]
struct IdtEntry {
    low     : u64,
    high    : u64,
}

const IDT_TARGET_MASK_1 : u64 = 0x0000_0000_0000_ffff;
const IDT_TARGET_MASK_2 : u64 = 0x0000_0000_ffff_0000;
const IDT_TARGET_MASK_3 : u64 = 0xffff_ffff_0000_0000;

const IDT_TARGET_MASK_1_SHIFT   : u64 = 0;
const IDT_TARGET_MASK_2_SHIFT   : u64 = 48 - 16;
const IDT_TARGET_MASK_3_SHIFT   : u64 = 32;

const IDT_TYPE_MASK     : u64 = 0xeu64 << 40; // Only interrupt gates for now
const IDT_PRESENT_MASK  : u64 = 0x1u64 << 47;
const IDT_CS_SHIFT      : u64 = 16;

const IDT_IST_MASK      : u64 = 0x7;
const IDT_IST_SHIFT     : u64 = 32;

impl IdtEntry {
    const fn create(target : VirtAddr, cs : u16, ist : u8) -> Self {
        let vaddr = target as u64;
        let cs_mask = (cs as u64) << IDT_CS_SHIFT;
        let ist_mask = ((ist as u64) & IDT_IST_MASK) << IDT_IST_SHIFT;
        let low = (vaddr & IDT_TARGET_MASK_1) << IDT_TARGET_MASK_1_SHIFT |
              (vaddr & IDT_TARGET_MASK_2) << IDT_TARGET_MASK_2_SHIFT |
              IDT_TYPE_MASK | IDT_PRESENT_MASK | cs_mask | ist_mask;
        let high = (vaddr & IDT_TARGET_MASK_3) >> IDT_TARGET_MASK_3_SHIFT;

        IdtEntry { low : low, high : high }
    }

    pub const fn entry(target : VirtAddr) -> Self {
        IdtEntry::create(target, SVSM_CS, 0)
    }

    pub const fn ist_entry(target : VirtAddr, ist : u8) -> Self {
        IdtEntry::create(target, SVSM_CS, ist)
    }

    pub const fn no_handler() -> Self {
        IdtEntry { low : 0, high : 0 }
    }
}

const IDT_ENTRIES : usize = 256;

#[repr(C, packed)]
struct IdtDesc {
    size    : u16,
    address : usize,
}

extern "C" {
    static idt_handler_array : u8;
}

type Idt = [IdtEntry; IDT_ENTRIES];

static mut GLOBAL_IDT : Idt = [IdtEntry::no_handler(); IDT_ENTRIES];

pub fn idt_base_limit() -> (u64, u32) {
    unsafe {
        let base = (&GLOBAL_IDT as *const Idt) as u64;
        let limit = (IDT_ENTRIES * mem::size_of::<IdtEntry>()) as u32;
        (base, limit)
    }
}

fn init_idt(idt : &mut Idt) {
    // Set IDT handlers
    for i in 0..IDT_ENTRIES {
        unsafe {
            let handler = ((&idt_handler_array as *const u8) as VirtAddr) + (32 * i);
            idt[i] = IdtEntry::entry(handler);
        }
    }
}

unsafe fn init_ist_vectors(idt : &mut Idt) {
    let handler = ((&idt_handler_array as *const u8) as VirtAddr) + (32 * DF_VECTOR);
    idt[DF_VECTOR] = IdtEntry::ist_entry(handler, IST_DF.try_into().unwrap());
}

fn load_idt(idt : &Idt) {
    let desc : IdtDesc = IdtDesc {
        size    : (IDT_ENTRIES * 16) as u16,
        address : idt.as_ptr() as VirtAddr,
    };

    unsafe { asm!("lidt (%rax)", in("rax") &desc, options(att_syntax)); }
}

pub fn early_idt_init() {
    unsafe {
        init_idt(&mut GLOBAL_IDT);
        load_idt(&GLOBAL_IDT);
    }
}

pub fn idt_init() {
    // Set IST vectors
    unsafe { init_ist_vectors(&mut GLOBAL_IDT); }
}

#[no_mangle]
fn generic_idt_handler(regs : &mut x86_regs) {
    if regs.vector == DF_VECTOR {
        let cr2 = read_cr2();
        let rip = regs.rip;
        let rsp = regs.rsp;
        println!("Double-Fault at RIP {:#018x} RSP: {:#018x} CR2: {:#018x}", rip, rsp, cr2);
    } else if regs.vector == GP_VECTOR {
        let rip = regs.rip;
        let err = regs.error_code;
        println!("General-Protection-Fault at RIP {:#018x} error code: {:#018x}", rip, err);
    } else if regs.vector == PF_VECTOR {
        let cr2 = read_cr2();
        let rip = regs.rip;
        let err = regs.error_code;
        println!("Page-Fault at RIP {:#018x} CR2: {:#018x} error code: {:#018x}", rip, cr2, err);
    } else {
        let err = regs.error_code;
        let vec = regs.vector;
        let rip = regs.rip;
        panic!("Unhandled exception {} RIP {:#018x} error code: {:#018x}", vec, rip, err);
    }

    loop { halt(); }
}

// Entry Code
global_asm!(r#"
        .text
    push_regs:
        pushq   %rax
        pushq   %rbx
        pushq   %rcx
        pushq   %rdx
        pushq   %rsi
        pushq   %rdi
        pushq   %rbp
        pushq   %r8
        pushq   %r9
        pushq   %r10
        pushq   %r11
        pushq   %r12
        pushq   %r13
        pushq   %r14
        pushq   %r15

        movq    %rsp, %rdi
        call    generic_idt_handler

        popq    %r15
        popq    %r14
        popq    %r13
        popq    %r12
        popq    %r11
        popq    %r10
        popq    %r9
        popq    %r8
        popq    %rbp
        popq    %rdi
        popq    %rsi
        popq    %rdx
        popq    %rcx
        popq    %rbx
        popq    %rax

        addq    $16, %rsp /* Skip vector and error code */

        iret

        .align 32
        .globl idt_handler_array
    idt_handler_array:
        i = 0
        .rept 32
        .align 32
        .if ((0x20027d00 >> i) & 1) == 0
        pushq   $0
        .endif
        pushq   $i  /* Vector Number */
        jmp push_regs
        i = i + 1
        .endr
        "#,
        options(att_syntax));
