//
// Copyright 2025, Capabilities Limited
//
// SPDX-License-Identifier: BSD-2-Clause
//
use crate::elf::{ElfFile, ElfFlagsRiscv};
use crate::sel4::{Arch, Config, Invocation, InvocationArgs};
use crate::sdf::SysMapPerms;
use crate::util::round_down;

// This must match the CHERI-seL4's block CheriCapMeta
#[derive(Debug, Clone, Copy)]
pub struct CheriRiscv64CapMeta {
    raw: u64,
}

impl CheriRiscv64CapMeta {
    pub fn new() -> Self {
        Self { raw: 0 }
    }

    pub fn raw(&self) -> u64 {
        self.raw
    }

    // === V: bit 0 ===
    pub fn set_v(&mut self, val: bool) {
        if val {
            self.raw |= 1 << 0;
        } else {
            self.raw &= !(1 << 0);
        }
    }

    // === M: bit 1 ===
    pub fn set_m(&mut self, val: bool) {
        if val {
            self.raw |= 1 << 1;
        } else {
            self.raw &= !(1 << 1);
        }
    }

    // === CT: bit 2 ===
    pub fn set_ct(&mut self, val: bool) {
        if val {
            self.raw |= 1 << 2;
        } else {
            self.raw &= !(1 << 2);
        }
    }

    // === AP: bits 32–63 ===
    pub fn set_ap(&mut self, val: u32) {
        self.raw = (self.raw & !(0xFFFF_FFFFu64 << 32)) | ((val as u64) << 32);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheriRiscv64CapPermissions;

#[allow(dead_code)]
impl CheriRiscv64CapPermissions {
    pub const PERMIT_STORE: u32 = 1 << 0;
    pub const LOAD_MUTABLE: u32 = 1 << 1;
    pub const PERMIT_EL: u32 = 1 << 2;
    pub const PERMIT_SL: u32 = 1 << 3;
    pub const GLOBAL: u32 = 1 << 4;
    pub const CAPABILITY: u32 = 1 << 5;

    pub const USER_00: u32 = 1 << 6;
    pub const USER_01: u32 = 1 << 7;
    pub const USER_02: u32 = 1 << 8;
    pub const USER_03: u32 = 1 << 9;

    pub const ACCESS_SYSTEM_REGISTERS: u32 = 1 << 16;
    pub const PERMIT_EXECUTE: u32 = 1 << 17;
    pub const PERMIT_LOAD: u32 = 1 << 18;
}

fn cheri_riscv_tcb_init_reg_context(
    config: &Config,
    system_invocations: &mut Vec<Invocation>,
    tcb_cptr: u64,
    vspace_cptr: u64,
    stack_size: u64,
    pd_elf_file: &ElfFile,
) {
    let purecap = (pd_elf_file.flags & (ElfFlagsRiscv::EfRiscvCapMode as u64)) != 0;

    if purecap {
        let code_segments = pd_elf_file.code_segments();
        let data_segments = pd_elf_file.data_segments();

        if code_segments.len() != 1 || data_segments.len() != 1 {
            eprintln!("CHERI Protection domain ELFs can only have one code segment and one data segment");
            std::process::exit(1);
        }

        /* Null DDC -- purecap won't have a valid DDC */
        system_invocations.push(Invocation::new(
            config,
            InvocationArgs::CheriWriteRegister {
                tcb: tcb_cptr,
                vspace_root: vspace_cptr,
                reg_idx: 35,
                cheri_base: 0,
                cheri_addr: 0,
                cheri_size: 0,
                cheri_meta: 0,
            },
        ));

        let mut meta = CheriRiscv64CapMeta::new();

        /* PCC */
        meta.set_v(true); // tag
        meta.set_ct(true); // sentry
        meta.set_m(false); // Capability Pointer Mode (capmode)
        meta.set_ap(u32::MAX & !(
            CheriRiscv64CapPermissions::PERMIT_STORE |
            CheriRiscv64CapPermissions::ACCESS_SYSTEM_REGISTERS
        ));
        system_invocations.push(Invocation::new(
            config,
            InvocationArgs::CheriWriteRegister {
                tcb: tcb_cptr,
                vspace_root: vspace_cptr,
                reg_idx: 0,
                cheri_base: code_segments[0].virt_addr,
                cheri_addr: pd_elf_file.entry,
                // XXX Make PCC cover both code and data segments, maybe refine later?
                cheri_size: data_segments[0].virt_addr + data_segments[0].data.len() as u64 - code_segments[0].virt_addr,
                cheri_meta: meta.raw(),
            },
        ));

        /* CSP */
        meta.set_ct(false); // sentry
        meta.set_ap(u32::MAX & !CheriRiscv64CapPermissions::PERMIT_EXECUTE);
        system_invocations.push(Invocation::new(
            config,
            InvocationArgs::CheriWriteRegister {
                tcb: tcb_cptr,
                vspace_root: vspace_cptr,
                reg_idx: 2,
                cheri_base: config.pd_stack_top() - stack_size,
                cheri_addr: config.pd_stack_top(),
                cheri_size: stack_size,
                cheri_meta: meta.raw(),
            },
        ));

        /* CA0 -- Code cap passed to crt0 to construct code caps from */
        meta.set_ap(u32::MAX & !(
            CheriRiscv64CapPermissions::PERMIT_STORE |
            CheriRiscv64CapPermissions::ACCESS_SYSTEM_REGISTERS
        ));
        system_invocations.push(Invocation::new(
            config,
            InvocationArgs::CheriWriteRegister {
                tcb: tcb_cptr,
                vspace_root: vspace_cptr,
                reg_idx: 16,
                cheri_base: code_segments[0].virt_addr,
                cheri_addr: code_segments[0].virt_addr,
                cheri_size: code_segments[0].data.len() as u64,
                cheri_meta: meta.raw(),
            },
        ));

        /* CA1 -- Data cap passed to crt0 to construct code caps from */
        meta.set_ap(u32::MAX & !CheriRiscv64CapPermissions::PERMIT_EXECUTE);
        system_invocations.push(Invocation::new(
            config,
            InvocationArgs::CheriWriteRegister {
                tcb: tcb_cptr,
                vspace_root: vspace_cptr,
                reg_idx: 17,
                cheri_base: data_segments[0].virt_addr,
                cheri_addr: data_segments[0].virt_addr,
                cheri_size: data_segments[0].data.len() as u64,
                cheri_meta: meta.raw(),
            },
        ));
    } else {
        // Hybrid/legacy ELFs. Set PCC/DDC to almighty

        let mut meta = CheriRiscv64CapMeta::new();

        /* PCC */
        meta.set_v(true); // tag
        meta.set_ct(true); // sentry
        meta.set_m(true); // Integer Pointer Mode
        meta.set_ap(u32::MAX);
        system_invocations.push(Invocation::new(
            config,
            InvocationArgs::CheriWriteRegister {
                tcb: tcb_cptr,
                vspace_root: vspace_cptr,
                reg_idx: 0,
                cheri_base: 0,
                cheri_addr: pd_elf_file.entry,
                cheri_size: u64::MAX,
                cheri_meta: meta.raw(),
            },
        ));

        /* DDC */
        meta.set_ct(false); // sentry
        system_invocations.push(Invocation::new(
            config,
            InvocationArgs::CheriWriteRegister {
                tcb: tcb_cptr,
                vspace_root: vspace_cptr,
                reg_idx: 35,
                cheri_base: 0,
                cheri_addr: 0,
                cheri_size: u64::MAX,
                cheri_meta: meta.raw(),
            },
        ));
    }
}

pub fn cheri_arch_tcb_init_reg_context(
    config: &Config,
    system_invocations: &mut Vec<Invocation>,
    tcb_cptr: u64,
    vspace_cptr: u64,
    stack_size: u64,
    pd_elf_file: &ElfFile,
) {
    match config.arch {
        Arch::Riscv64 => cheri_riscv_tcb_init_reg_context(
            config,
            system_invocations,
            tcb_cptr,
            vspace_cptr,
            stack_size,
            pd_elf_file,
        ),
        _ => {
            eprintln!("Only CHERI-RISC-V 64-bit is supported at the moment");
            std::process::exit(1);
        }
    }
}

fn cheri_riscv_write_sym_cap(
    config: &Config,
    system_invocations: &mut Vec<Invocation>,
    pd_elf_file: &ElfFile,
    tcb_cptr: u64,
    vspace_cptr: u64,
    page_cptr: u64,
    vaddr: u64,
    addr: u64,
    size: u64,
    map_perms: u8,
) {
    let purecap = (pd_elf_file.flags & (ElfFlagsRiscv::EfRiscvCapMode as u64)) != 0;

    if purecap {
        let mut meta = CheriRiscv64CapMeta::new();
        let mut cap_perms = 0;

        if map_perms & SysMapPerms::Read as u8 != 0 {
            cap_perms |= CheriRiscv64CapPermissions::PERMIT_LOAD;
        }

        if map_perms & SysMapPerms::Write as u8 != 0 {
            cap_perms |= CheriRiscv64CapPermissions::PERMIT_STORE;
        }

        if map_perms & SysMapPerms::Execute as u8 != 0 {
            cap_perms |= CheriRiscv64CapPermissions::PERMIT_EXECUTE;
        }

        if map_perms & SysMapPerms::Cheri as u8 != 0 {
            cap_perms |= CheriRiscv64CapPermissions::CAPABILITY;
        }

        meta.set_v(true); // tag
        meta.set_m(false); // Capability Pointer Mode (capmode)
        meta.set_ap(cap_perms);

        system_invocations.push(Invocation::new(
            config,
            InvocationArgs::CheriWriteMemoryCap {
                tcb: tcb_cptr,
                vspace_root: vspace_cptr,
                page: page_cptr,
                vaddr,
                cheri_base: addr,
                cheri_addr: addr,
                cheri_size: size,
                cheri_meta: meta.raw(),
            },
        ));
    }
}

pub fn cheri_arch_write_sym_cap(
    config: &Config,
    system_invocations: &mut Vec<Invocation>,
    pd_page_descriptors: &[(u64, usize, u64, u64, u64, u64, u64)],
    pd_elf_file: &ElfFile,
    sym: &str,
    pd_idx: usize,
    tcb_cptr: u64,
    vspace_cptr: u64,
    addr: u64,
    size: u64,
    map_perms: u8,
) {
    let (sym_vaddr, _) = pd_elf_file
        .find_symbol(sym)
        .unwrap_or_else(|_| panic!("Could not find {}", sym));
    let symbol_page = round_down(sym_vaddr, size);

    let page_cptr = pd_page_descriptors
        .iter()
        .find(|(_, pdidx, vaddr, _, _, _, _)| *vaddr == symbol_page && *pdidx == pd_idx)
        .map(|(cap_cptr, _, _, _, _, _, _)| *cap_cptr)
        .unwrap_or(0);

    match config.arch {
        Arch::Riscv64 => cheri_riscv_write_sym_cap(
            config,
            system_invocations,
            pd_elf_file,
            tcb_cptr,
            vspace_cptr,
            page_cptr,
            sym_vaddr,
            addr,
            size,
            map_perms,
        ),
        _ => {
            eprintln!("Only CHERI-RISC-V 64-bit is supported at the moment");
            std::process::exit(1);
        }
    }
}
