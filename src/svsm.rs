#![no_std]
#![no_main]

pub mod kernel_launch;
pub mod pagetable;
pub mod locking;
pub mod memory;
pub mod types;
pub mod util;
pub mod msr;
pub mod gdt;

use kernel_launch::KernelLaunchInfo;
use types::{VirtAddr, PhysAddr};
use core::panic::PanicInfo;
use core::arch::global_asm;
use memory::memory_init;
use locking::SpinLock;
use pagetable::PageTable;
use gdt::load_gdt;

#[macro_use]
extern crate bitflags;

/*
 * Launch protocol:
 *
 * The stage2 loader will map and load the svsm binary image and jump to
 * startup_64.
 *
 * %rdx will contain the offset from the phys->virt offset
 * %r8  will contain a pointer to the KernelLaunchInfo structure
 */
global_asm!(r#"
		.text
		.section ".startup.text","ax"
		.code64
		.quad	0xffffff8000000000
		.quad	startup_64
		
		.org	0x80

		.globl	startup_64
	startup_64:
		/* Save PHYS_OFFSET */
		movq	%rdx, PHYS_OFFSET(%rip)

		/* Setup stack */
		leaq bsp_stack_end(%rip), %rsp

		/* Clear BSS */
		xorq	%rax, %rax
		leaq	_bss(%rip), %rdi
		leaq	_ebss(%rip), %rcx
		subq	%rdi, %rcx
		shrq	$3, %rcx
		rep stosq

		/* Jump to rust code */
		movq	%r8, %rdi
		jmp	svsm_main
		
		.data

		.globl PHYS_OFFSET
	PHYS_OFFSET:
		.quad 0

		.align 4096
	bsp_stack:
		.fill 4096, 1, 0
	bsp_stack_end:
	
		"#, options(att_syntax));

extern "C" {
	pub static PHYS_OFFSET : u64;
	pub static heap_start : u8;
}

pub fn allocate_pt_page() -> *mut u8 {
	let pt_page : VirtAddr = memory::allocate_zeroed_page().expect("Failed to allocate pgtable page");

	pt_page as *mut u8
}

pub fn virt_to_phys(vaddr : VirtAddr) -> PhysAddr {
	memory::virt_to_phys(vaddr)
}

pub fn phys_to_virt(paddr : PhysAddr) -> VirtAddr {
	memory::phys_to_virt(paddr)
}

#[no_mangle]
pub extern "C" fn svsm_main(launch_info : &KernelLaunchInfo) {
	load_gdt();
	memory_init(launch_info);
	panic!("Road ends here!");
}

#[panic_handler]
fn panic(_info : &PanicInfo) -> ! {
	loop { }
}