use crate::{control::{Cr0, Cr3, Cr4, Efer}, regs::{RegFile, Gpr}, flags::RFlags, segments::{SegState, DescriptorTableReg, SegmentSelector, SegmentCache, SegReg, instr_mov_sreg, instr_lss32, resolve_far_call32_code, resolve_call_gate, resolve_far_jmp32_code, resolve_jmp_gate32, resolve_iret32, resolve_retf32}, msr::MsrMap, dr::DebugRegs, feature::FeatureSet, exceptions::Exception};
use crate::memory::Memory;
use mmu_tlb::{PageWalker, Walker32, PhysMem as WalkerPhysMem, TranslateResult as PwTranslateResult, PageFault as PwPageFault, Tlb, TlbKey, Pcid, PteFlags};

#[derive(Debug, Default)]
pub struct Cpu {
    pub regs: RegFile,
    pub rflags: RFlags,
    pub segs: SegState,
    pub gdtr: DescriptorTableReg,
    pub idtr: DescriptorTableReg,
    pub ldtr: (SegmentSelector, SegmentCache),
    pub tr: (SegmentSelector, SegmentCache),
    pub cr0: Cr0,
    pub cr3: Cr3,
    pub cr4: Cr4,
    pub efer: Efer,
    pub msrs: MsrMap,
    pub dr: DebugRegs,
    pub features: FeatureSet,
    pub tlb: Tlb,
}

impl Cpu {
    pub fn new() -> Self { Self::default() }

    pub fn reset(&mut self) {
        *self = Self::default();
        // Architectural reset defaults
        self.rflags = RFlags::ID; // CPUID present by default
        self.cr0 = Cr0::empty();
        self.cr4 = Cr4::empty();
        self.efer = Efer::empty();
        self.regs.rip = 0xFFF0; // typical x86 reset vector, real mode
        self.gdtr = DescriptorTableReg { base: 0, limit: 0 };
        self.idtr = DescriptorTableReg { base: 0, limit: 0 };
    }

    pub fn step(&mut self) -> Result<(), Exception> {
        // Placeholder until decoder/executor wired
        Err(crate::exceptions::Exception::new(crate::exceptions::Vector::UD, None))
    }

    #[inline]
    pub fn current_cpl(&self) -> u8 { self.segs.cs.1.flags.dpl() }

    pub fn exec_mov_sreg(&mut self, mem: &dyn Memory, seg: SegReg, sel: SegmentSelector) -> Result<(), Exception> {
        let cpl = self.current_cpl();
        instr_mov_sreg(self, mem, seg, sel, cpl)
    }

    pub fn exec_lss32(&mut self, mem: &dyn Memory, ptr: u64) -> Result<u32, Exception> {
        let cpl = self.current_cpl();
        instr_lss32(self, mem, ptr, cpl)
    }

    fn ss_base(&self) -> u64 { self.segs.ss.1.base }

    fn push32(&mut self, mem: &mut dyn Memory, val: u32) -> Result<(), Exception> {
        let esp = self.regs.get32(Gpr::RSP).wrapping_sub(4);
        let lin = self.ss_base().wrapping_add(esp as u64);
        mem.write(lin, &val.to_le_bytes()).map_err(|_| Exception::new(crate::exceptions::Vector::SS, Some(0)))?;
        self.regs.set32(Gpr::RSP, esp);
        Ok(())
    }

    fn push16(&mut self, mem: &mut dyn Memory, val: u16) -> Result<(), Exception> {
        let esp = self.regs.get32(Gpr::RSP).wrapping_sub(2);
        let lin = self.ss_base().wrapping_add(esp as u64);
        mem.write(lin, &val.to_le_bytes()).map_err(|_| Exception::new(crate::exceptions::Vector::SS, Some(0)))?;
        self.regs.set32(Gpr::RSP, esp);
        Ok(())
    }

    pub fn exec_far_call32_code(&mut self, mem: &mut dyn Memory, sel: SegmentSelector, offset: u32) -> Result<(), Exception> {
        let cpl = self.current_cpl();
        let res = resolve_far_call32_code(self, mem, cpl, sel, offset)?;
        let ret_eip = self.regs.rip as u32;
        let (_cs_sel, _cs_cache) = self.segs.get(SegReg::CS);
        self.push32(mem, ret_eip)?;
        self.push16(mem, _cs_sel.0)?;
        self.segs.set(SegReg::CS, res.target_sel, res.target_cache);
        self.regs.rip = res.target_offset as u64;
        Ok(())
    }

    pub fn exec_call_gate32(&mut self, mem: &mut dyn Memory, gate_sel: SegmentSelector) -> Result<(), Exception> {
        let cpl = self.current_cpl();
        let res = resolve_call_gate(self, mem, gate_sel, cpl)?;
        let ret_eip = self.regs.rip as u32;
        let (cs_sel, _cs_cache) = self.segs.get(SegReg::CS);
        // Capture caller stack for parameter copy (if privilege change occurs)
        let (old_ss_sel, old_ss_cache) = self.segs.get(SegReg::SS);
        let old_esp = self.regs.get32(Gpr::RSP);
        if let Some((ss_sel, ss_cache, new_esp)) = res.new_ss {
            self.segs.set(SegReg::SS, ss_sel, ss_cache);
            self.regs.set32(Gpr::RSP, new_esp);
        }
        self.push32(mem, ret_eip)?;
        self.push16(mem, cs_sel.0)?;
        // Copy parameter words per gate param_count (only when ring change occurred)
        if let Some((_nss_sel, nss_cache, _)) = res.new_ss {
            if res.param_count > 0 {
                // Gate defines parameter unit (16-bit vs 32-bit)
                let unit: u32 = if res.param_unit == 0 { 0 } else { res.param_unit as u32 };
                if unit == 0 { /* not a call gate (shouldn't happen) */ }
                let total: u32 = (res.param_count as u32) * unit;
                let dst_rsp = self.regs.get32(Gpr::RSP);
                let src_base = old_ss_cache.base;
                let dst_base = nss_cache.base;
                let ret_bytes: u32 = (res.ret_ip_size as u32) + 2; // return IP size + CS(2)
                let old_user = cpl == 3;
                let new_user = res.new_cpl == 3;
                let mut i: u32 = 0;
                while i < total {
                    // Segment limit checks for source and destination windows
                    Self::seg_check_limit(SegReg::SS, &old_ss_cache, old_esp.wrapping_add(i) as u64, unit as u64)?;
                    Self::seg_check_limit(SegReg::SS, &nss_cache, dst_rsp.wrapping_add(ret_bytes).wrapping_add(i) as u64, unit as u64)?;
                    // Copy byte-wise to engage paging and raise PF appropriately
                    let mut j: u32 = 0;
                    while j < unit {
                        let src_lin = src_base.wrapping_add(old_esp.wrapping_add(i).wrapping_add(j) as u64);
                        let dst_lin = dst_base.wrapping_add(dst_rsp.wrapping_add(ret_bytes).wrapping_add(i).wrapping_add(j) as u64);
                        let tr_s = self.translate_lin32(mem, src_lin, false, old_user, false).map_err(|pf| Exception::new(crate::exceptions::Vector::PF, Some(pf.code)))?;
                        let tr_d = self.translate_lin32(mem, dst_lin, true, new_user, false).map_err(|pf| Exception::new(crate::exceptions::Vector::PF, Some(pf.code)))?;
                        let mut b = [0u8;1];
                        mem.read(tr_s.phys, &mut b).map_err(|_| Exception::new(crate::exceptions::Vector::PF, Some(0)))?;
                        mem.write(tr_d.phys, &b).map_err(|_| Exception::new(crate::exceptions::Vector::PF, Some(0)))?;
                        j += 1;
                    }
                    i += unit;
                }
            }
            // Note: The caller's stack is not adjusted here; per spec, `lret imm16` in the callee adjusts
            // the caller's stack (resolve_retf32 already applies the immediate to the destination stack).
            let _ = old_ss_sel; // silence potential warning if unused under cfg
        }
        self.segs.set(SegReg::CS, res.target_sel, res.target_cache);
        self.regs.rip = res.target_offset as u64;
        Ok(())
    }

    pub fn exec_call_gate16(&mut self, mem: &mut dyn Memory, gate_sel: SegmentSelector) -> Result<(), Exception> {
        let cpl = self.current_cpl();
        let res = resolve_call_gate(self, mem, gate_sel, cpl)?;
        let ret_ip16 = self.regs.rip as u16;
        let (cs_sel, _cs_cache) = self.segs.get(SegReg::CS);
        // Capture caller stack for parameter copy
        let (old_ss_sel, old_ss_cache) = self.segs.get(SegReg::SS);
        let old_sp = self.regs.get16(Gpr::RSP);
        if let Some((ss_sel, ss_cache, new_sp32)) = res.new_ss {
            self.segs.set(SegReg::SS, ss_sel, ss_cache);
            self.regs.set32(Gpr::RSP, new_sp32);
        }
        self.push16(mem, ret_ip16)?;
        self.push16(mem, cs_sel.0)?;
        if let Some((_nss_sel, nss_cache, _)) = res.new_ss {
            if res.param_count > 0 {
                let unit: u32 = if res.param_unit == 0 { 0 } else { res.param_unit as u32 };
                if unit == 0 { /* not a call gate */ }
                let total: u32 = (res.param_count as u32) * unit;
                let dst_sp = self.regs.get32(Gpr::RSP);
                let src_base = old_ss_cache.base;
                let dst_base = nss_cache.base;
                let ret_bytes: u32 = (res.ret_ip_size as u32) + 2; // IP + CS
                let old_user = cpl == 3;
                let new_user = res.new_cpl == 3;
                let mut i: u32 = 0;
                while i < total {
                    Self::seg_check_limit(SegReg::SS, &old_ss_cache, (old_sp as u32).wrapping_add(i) as u64, unit as u64)?;
                    Self::seg_check_limit(SegReg::SS, &nss_cache, (dst_sp).wrapping_add(ret_bytes).wrapping_add(i) as u64, unit as u64)?;
                    let mut j: u32 = 0;
                    while j < unit {
                        let src_lin = src_base.wrapping_add((old_sp as u32).wrapping_add(i).wrapping_add(j) as u64);
                        let dst_lin = dst_base.wrapping_add(dst_sp.wrapping_add(ret_bytes).wrapping_add(i).wrapping_add(j) as u64);
                        let tr_s = self.translate_lin32(mem, src_lin, false, old_user, false).map_err(|pf| Exception::new(crate::exceptions::Vector::PF, Some(pf.code)))?;
                        let tr_d = self.translate_lin32(mem, dst_lin, true, new_user, false).map_err(|pf| Exception::new(crate::exceptions::Vector::PF, Some(pf.code)))?;
                        let mut b = [0u8;1];
                        mem.read(tr_s.phys, &mut b).map_err(|_| Exception::new(crate::exceptions::Vector::PF, Some(0)))?;
                        mem.write(tr_d.phys, &b).map_err(|_| Exception::new(crate::exceptions::Vector::PF, Some(0)))?;
                        j += 1;
                    }
                    i += unit;
                }
            }
            let _ = old_ss_sel;
        }
        self.segs.set(SegReg::CS, res.target_sel, res.target_cache);
        self.regs.rip = res.target_offset as u64;
        Ok(())
    }

    pub fn exec_far_jmp32_code(&mut self, mem: &dyn Memory, sel: SegmentSelector, offset: u32) -> Result<(), Exception> {
        let cpl = self.current_cpl();
        let res = resolve_far_jmp32_code(self, mem, cpl, sel, offset)?;
        self.segs.set(SegReg::CS, res.target_sel, res.target_cache);
        self.regs.rip = res.target_offset as u64;
        Ok(())
    }

    pub fn exec_jmp_gate32(&mut self, mem: &mut dyn Memory, gate_sel: SegmentSelector) -> Result<(), Exception> {
        let cpl = self.current_cpl();
        let res = resolve_jmp_gate32(self, mem, gate_sel, cpl)?;
        if let Some((ss_sel, ss_cache, new_esp)) = res.new_ss {
            self.segs.set(SegReg::SS, ss_sel, ss_cache);
            self.regs.set32(Gpr::RSP, new_esp);
        }
        self.segs.set(SegReg::CS, res.target_sel, res.target_cache);
        self.regs.rip = res.target_offset as u64;
        Ok(())
    }

    pub fn exec_iret32(&mut self, mem: &dyn Memory) -> Result<(), Exception> {
        let cpl = self.current_cpl();
        let cur_ss = self.segs.get(SegReg::SS);
        let esp = self.regs.get32(Gpr::RSP);
        let (res, new_sp) = resolve_iret32(self, mem, cpl, cur_ss, esp)?;
        let mut used_new_stack = false;
        if let Some((ss_sel, ss_cache, new_esp)) = res.new_ss {
            self.segs.set(SegReg::SS, ss_sel, ss_cache);
            self.regs.set32(Gpr::RSP, new_esp);
            used_new_stack = true;
        }
        self.segs.set(SegReg::CS, res.target_sel, res.target_cache);
        self.regs.rip = res.target_offset as u64;
        // Simplified rflags load for now
        let new = (self.rflags.bits() & !0xFFFF_FFFF) | (res.rflags as u64);
        self.rflags = crate::flags::RFlags::from_bits_retain(new);
        if !used_new_stack { self.regs.set32(Gpr::RSP, new_sp); }
        Ok(())
    }

    pub fn exec_retf32(&mut self, mem: &dyn Memory, imm16: u16) -> Result<(), Exception> {
        let cpl = self.current_cpl();
        let cur_ss = self.segs.get(SegReg::SS);
        let esp = self.regs.get32(Gpr::RSP);
        let (res, new_sp) = resolve_retf32(self, mem, cpl, cur_ss, esp, imm16)?;
        let mut used_new_stack = false;
        if let Some((ss_sel, ss_cache, new_esp)) = res.new_ss {
            self.segs.set(SegReg::SS, ss_sel, ss_cache);
            self.regs.set32(Gpr::RSP, new_esp);
            used_new_stack = true;
        }
        self.segs.set(SegReg::CS, res.target_sel, res.target_cache);
        self.regs.rip = res.target_offset as u64;
        if !used_new_stack { self.regs.set32(Gpr::RSP, new_sp); }
        Ok(())
    }

    // Linear -> physical translation using 32-bit walker
    pub fn translate_lin32(&mut self, mem: &mut dyn Memory, lin: u64, write: bool, user: bool, exec: bool) -> Result<PwTranslateResult, PwPageFault> {
        struct MemPhys<'a> { m: &'a mut dyn Memory }
        impl<'a> WalkerPhysMem for MemPhys<'a> {
            fn read_u32(&self, pa: u64) -> Result<u32, mmu_tlb::PhysMemError> {
                let mut buf = [0u8;4];
                self.m.read(pa, &mut buf).map_err(|_| mmu_tlb::PhysMemError::Bad(pa))?;
                Ok(u32::from_le_bytes(buf))
            }
            fn write_u32(&mut self, pa: u64, val: u32) -> Result<(), mmu_tlb::PhysMemError> {
                self.m.write(pa, &val.to_le_bytes()).map_err(|_| mmu_tlb::PhysMemError::Bad(pa))
            }
        }

        // If paging disabled, identity mapping
        if !self.cr0.contains(crate::control::Cr0::PG) { return Ok(PwTranslateResult { phys: lin, flags: mmu_tlb::PteFlags::P }); }

        // TLB lookup
        let pcid = if self.cr4.contains(crate::control::Cr4::PCIDE) { self.cr3.pcid.map(Pcid) } else { None };
        let key = TlbKey { pcid, page: lin >> 12 };
        if let Some(ent) = self.tlb.lookup(key) {
            let phys = (ent.phys_page << 12) | (lin & 0xFFF);
            // Permission checks based on cached flags
            if write && !ent.flags.contains(PteFlags::RW) { return Err(PwPageFault { lin, kind: mmu_tlb::PageFaultKind::Protection, code: (1<<0) | (1<<1) | ((user as u32)<<2) }); }
            if user && !ent.flags.contains(PteFlags::US) { return Err(PwPageFault { lin, kind: mmu_tlb::PageFaultKind::Protection, code: (1<<0) | ((write as u32)<<1) | (1<<2) }); }
            return Ok(PwTranslateResult { phys, flags: ent.flags });
        }
        let cr3 = self.cr3.pml4 as u32;
        let pse = self.cr4.contains(crate::control::Cr4::PSE);
        let mut mp = MemPhys { m: mem };
        let mut walker = Walker32 { cr3, pse, mem: &mut mp };
        let tr = walker.translate(lin, write, user, exec)?;
        self.tlb.insert(key, mmu_tlb::TlbEntry { phys_page: tr.phys >> 12, flags: tr.flags });
        Ok(tr)
    }

    pub fn invlpg(&mut self, lin: u64) {
        let pcid = if self.cr4.contains(crate::control::Cr4::PCIDE) { self.cr3.pcid.map(Pcid) } else { None };
        let key = TlbKey { pcid, page: lin >> 12 };
        self.tlb.invlpg(key);
    }

    pub fn write_cr3_and_flush(&mut self, new_pml4: u64, new_pcid: Option<u16>) {
        self.cr3.pml4 = new_pml4;
        self.cr3.pcid = new_pcid;
        // Simplified: flush all on CR3 write
        self.tlb.flush_all();
    }

    // Segmented memory access helpers (32-bit protected mode path)
    fn seg_check_limit(seg: SegReg, cache: &SegmentCache, offset: u64, size: u64) -> Result<(), Exception> {
        // Limit is applied to offset from base
        let limit = if cache.flags.contains(crate::segments::DescriptorFlags::G) {
            ((cache.limit as u64) << 12) | 0xFFF
        } else {
            cache.limit as u64
        };
        let end = offset.checked_add(size - 1).ok_or(Exception::new(crate::exceptions::Vector::GP, Some(0)))?;
        let expand_down = cache.flags.contains(crate::segments::DescriptorFlags::DC) && !cache.flags.contains(crate::segments::DescriptorFlags::EXEC);
        let db = cache.flags.contains(crate::segments::DescriptorFlags::DB);
        let max_off = if db { 0xFFFF_FFFFu64 } else { 0xFFFFu64 };
        let fault_vec = if matches!(seg, SegReg::SS) { crate::exceptions::Vector::SS } else { crate::exceptions::Vector::GP };
        if expand_down {
            // For expand-down, valid range is (limit+1 ..= max_off)
            if end <= limit || end > max_off || offset <= limit { return Err(Exception::new(fault_vec, Some(0))); }
        } else {
            if end > limit { return Err(Exception::new(fault_vec, Some(0))); }
        }
        Ok(())
    }

    pub fn mem_read_u8(&mut self, mem: &mut dyn Memory, seg: SegReg, offset: u64) -> Result<u8, Exception> {
        let (_sel, cache) = self.segs.get(seg);
        Self::seg_check_limit(seg, &cache, offset, 1)?;
        let lin = cache.base.wrapping_add(offset);
        let user = self.current_cpl() == 3;
        let tr = self.translate_lin32(mem, lin, false, user, false).map_err(|pf| Exception::new(crate::exceptions::Vector::PF, Some(pf.code)))?;
        let mut b = [0u8;1];
        mem.read(tr.phys, &mut b).map_err(|_| Exception::new(crate::exceptions::Vector::PF, Some(0)))?;
        Ok(b[0])
    }

    pub fn mem_write_u8(&mut self, mem: &mut dyn Memory, seg: SegReg, offset: u64, val: u8) -> Result<(), Exception> {
        let (_sel, cache) = self.segs.get(seg);
        Self::seg_check_limit(seg, &cache, offset, 1)?;
        let lin = cache.base.wrapping_add(offset);
        let user = self.current_cpl() == 3;
        let tr = self.translate_lin32(mem, lin, true, user, false).map_err(|pf| Exception::new(crate::exceptions::Vector::PF, Some(pf.code)))?;
        mem.write(tr.phys, &[val]).map_err(|_| Exception::new(crate::exceptions::Vector::PF, Some(0)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::segments::{DescriptorFlags};
    use crate::memory::{FlatMem, Memory};

    fn mk_seg_desc(base: u32, mut limit: u32, gran_4k: bool, typ: u8, s: bool, dpl: u8, present: bool, l: bool, db: bool, avl: bool) -> [u8;8] {
        if gran_4k { limit = (limit >> 12).min(0xFFFFF); }
        let mut raw = [0u8;8];
        raw[0] = (limit & 0xFF) as u8;
        raw[1] = ((limit >> 8) & 0xFF) as u8;
        raw[2] = (base & 0xFF) as u8;
        raw[3] = ((base >> 8) & 0xFF) as u8;
        raw[4] = ((base >> 16) & 0xFF) as u8;
        let mut access = 0u8;
        access |= (typ & 0x0F);
        access |= (if s {1} else {0}) << 4;
        access |= (dpl & 0x3) << 5;
        access |= (if present {1} else {0}) << 7;
        raw[5] = access;
        let mut flags = 0u8;
        flags |= ((limit >> 16) & 0x0F) as u8;
        flags |= (if avl {1} else {0}) << 4;
        flags |= (if l {1} else {0}) << 5;
        flags |= (if db {1} else {0}) << 6;
        flags |= (if gran_4k {1} else {0}) << 7;
        raw[6] = flags;
        raw[7] = ((base >> 24) & 0xFF) as u8;
        raw
    }

    fn write_desc(mem: &mut FlatMem, base: u64, index: u16, raw: [u8;8]) {
        let addr = base + (index as u64)*8;
        mem.write(addr, &raw).unwrap();
    }

    #[test]
    fn exec_mov_sreg_ds_ok() {
        let mut mem = FlatMem::new(0x10000);
        let gdtr = DescriptorTableReg { base: 0x1000, limit: 0x00FF };
        let data = mk_seg_desc(0x2000, 0xFFFF, false, 0b0010, true, 3, true, false, true, false);
        write_desc(&mut mem, gdtr.base, 3, data);

        let mut cpu = Cpu::new();
        cpu.gdtr = gdtr;
        // Set CS with CPL=3
        let mut cs_flags = DescriptorFlags::TYPE | DescriptorFlags::EXEC | DescriptorFlags::PRESENT;
        cs_flags = DescriptorFlags::from_bits_retain(cs_flags.bits() | (0b11 << 5));
        cpu.segs.set(SegReg::CS, SegmentSelector((4<<3)|3), SegmentCache { base: 0, limit: 0xFFFF, flags: cs_flags, valid: true });

        cpu.exec_mov_sreg(&mem, SegReg::DS, SegmentSelector((3<<3)|3)).unwrap();
        let (_sel, cache) = cpu.segs.get(SegReg::DS);
        assert!(cache.valid);
        assert_eq!(cache.base, 0x2000);
    }

    #[test]
    fn exec_lss32_loads_ss_and_returns_offset() {
        let mut mem = FlatMem::new(0x10000);
        let gdtr = DescriptorTableReg { base: 0x1000, limit: 0x00FF };
        let data = mk_seg_desc(0x3000, 0xFFFF, false, 0b0010, true, 3, true, false, true, false);
        write_desc(&mut mem, gdtr.base, 5, data);
        // pointer at 0x8000: offset 0xDEAD_BEEF, selector 5<<3|3
        mem.write(0x8000, &0xDEAD_BEEFu32.to_le_bytes()).unwrap();
        mem.write(0x8000 + 4, &(((5u16<<3)|3).to_le_bytes())).unwrap();

        let mut cpu = Cpu::new();
        cpu.gdtr = gdtr;
        // Set CPL=3 via CS
        let mut cs_flags = DescriptorFlags::TYPE | DescriptorFlags::EXEC | DescriptorFlags::PRESENT;
        cs_flags = DescriptorFlags::from_bits_retain(cs_flags.bits() | (0b11 << 5));
        cpu.segs.set(SegReg::CS, SegmentSelector((4<<3)|3), SegmentCache { base: 0, limit: 0xFFFF, flags: cs_flags, valid: true });

        let off = cpu.exec_lss32(&mem, 0x8000).unwrap();
        assert_eq!(off, 0xDEAD_BEEF);
        let (ss_sel, ss_cache) = cpu.segs.get(SegReg::SS);
        assert_eq!(ss_sel.index(), 5);
        assert!(ss_cache.valid);
        assert_eq!(ss_cache.base, 0x3000);
    }

    #[test]
    fn exec_far_call32_code_pushes_return() {
        let mut mem = FlatMem::new(0x20000);
        let gdtr = DescriptorTableReg { base: 0x1000, limit: 0x00FF };
        // current CS idx 4 (CPL=3)
        let mut cs_flags = DescriptorFlags::TYPE | DescriptorFlags::EXEC | DescriptorFlags::PRESENT;
        cs_flags = DescriptorFlags::from_bits_retain(cs_flags.bits() | (0b11 << 5));
        // target code idx 3 (DPL=3)
        let code3 = mk_seg_desc(0x4000, 0xFFFF, false, 0b1010, true, 3, true, false, true, false);
        write_desc(&mut mem, gdtr.base, 3, code3);
        let mut cpu = Cpu::new();
        cpu.gdtr = gdtr;
        cpu.segs.set(SegReg::CS, SegmentSelector((4<<3)|3), SegmentCache { base: 0, limit: 0xFFFF, flags: cs_flags, valid: true });
        // SS base 0, ESP
        cpu.segs.set(SegReg::SS, SegmentSelector((5<<3)|3), SegmentCache { base: 0, limit: 0xFFFF, flags: DescriptorFlags::TYPE | DescriptorFlags::RW | DescriptorFlags::PRESENT, valid: true });
        cpu.regs.set32(Gpr::RSP, 0x9000);
        cpu.regs.rip = 0x1111;

        cpu.exec_far_call32_code(&mut mem, SegmentSelector((3<<3)|3), 0x2222).unwrap();
        // Return pushed
        // After pushes: ESP = 0x9000 - 6
        assert_eq!(cpu.regs.get32(Gpr::RSP), 0x9000 - 6);
        let mut buf = [0u8;4];
        mem.read((0x9000 - 4) as u64, &mut buf).unwrap();
        assert_eq!(u32::from_le_bytes(buf), 0x1111);
        let mut b2 = [0u8;2];
        mem.read((0x9000 - 6) as u64, &mut b2).unwrap();
        assert_eq!(u16::from_le_bytes(b2), (4u16<<3)|3);
        // Target loaded
        let (cs_sel, _cs_cache) = cpu.segs.get(SegReg::CS);
        assert_eq!(cs_sel.index(), 3);
        assert_eq!(cpu.regs.rip as u32, 0x2222);
    }

    #[test]
    fn exec_call_gate32_ring_change() {
        let mut mem = FlatMem::new(0x40000);
        let gdtr = DescriptorTableReg { base: 0x1000, limit: 0x00FF };
        // target code idx 2 DPL=0
        let code0 = mk_seg_desc(0x5000, 0xFFFF, false, 0b1010, true, 0, true, false, true, false);
        write_desc(&mut mem, gdtr.base, 2, code0);
        // data idx 5 DPL=0 for SS0
        let data0 = mk_seg_desc(0x6000, 0xFFFF, false, 0b0010, true, 0, true, false, true, false);
        write_desc(&mut mem, gdtr.base, 5, data0);
        // TSS idx 6 with ESP0=0x8000, SS0=5<<3
        let tss_base = 0x3000u64;
        mem.write(tss_base + 0x04, &0x8000u32.to_le_bytes()).unwrap();
        mem.write(tss_base + 0x08, &((5u16<<3).to_le_bytes())).unwrap();
        let tss_desc = mk_seg_desc(tss_base as u32, 0x0067, false, 0b1001, false, 0, true, false, true, false);
        write_desc(&mut mem, gdtr.base, 6, tss_desc);
        // gate idx 1 to CS=2
        let gate = mk_seg_desc(0, 0, false, 0, false, 0, false, false, false, false); // placeholder to fill slot
        // Use helper from segments tests would be ideal; simplify: reuse call gate maker in that module
        // Instead, write a minimal 8-byte gate here:
        let mut raw = [0u8;8];
        let off = 0x1234u32;
        raw[0] = (off & 0xFF) as u8; raw[1] = ((off>>8)&0xFF) as u8;
        raw[2] = ( (2u16<<3) & 0xFF) as u8; raw[3] = (((2u16<<3)>>8)&0xFF) as u8;
        raw[4] = 0; raw[5] = 0x80 | 0x0C | (3<<5); // present, call gate 32, DPL=3
        raw[6] = ((off>>16)&0xFF) as u8; raw[7] = ((off>>24)&0xFF) as u8;
        write_desc(&mut mem, gdtr.base, 1, raw);

        let mut cpu = Cpu::new();
        cpu.gdtr = gdtr;
        // current CS idx 4 (CPL=3)
        let mut cs_flags = DescriptorFlags::TYPE | DescriptorFlags::EXEC | DescriptorFlags::PRESENT;
        cs_flags = DescriptorFlags::from_bits_retain(cs_flags.bits() | (0b11 << 5));
        cpu.segs.set(SegReg::CS, SegmentSelector((4<<3)|3), SegmentCache { base: 0, limit: 0xFFFF, flags: cs_flags, valid: true });
        super::super::segments::instr_ltr(&mut cpu, &mut mem, SegmentSelector(6<<3)).unwrap();
        cpu.segs.set(SegReg::SS, SegmentSelector((7<<3)|3), SegmentCache { base: 0, limit: 0xFFFF, flags: DescriptorFlags::TYPE | DescriptorFlags::RW | DescriptorFlags::PRESENT, valid: true });
        cpu.regs.set32(Gpr::RSP, 0x9000);
        cpu.regs.rip = 0x1111;

        cpu.exec_call_gate32(&mut mem, SegmentSelector((1<<3)|3)).unwrap();
        // ring change occurred: SS points to idx 5, ESP=0x8000
        let (ss_sel, ss_cache) = cpu.segs.get(SegReg::SS);
        assert_eq!(ss_sel.index(), 5);
        assert_eq!(cpu.regs.get32(Gpr::RSP), 0x8000 - 6);
        // return pushed on new stack
        let mut b4 = [0u8;4];
        mem.read((0x8000 - 4) as u64 + ss_cache.base, &mut b4).unwrap();
        assert_eq!(u32::from_le_bytes(b4), 0x1111);
    }

    #[test]
    fn jmp_gate32_dpl_rpl_checks_and_success() {
        let mut mem = FlatMem::new(0x40000);
        let gdtr = DescriptorTableReg { base: 0x1000, limit: 0x00FF };
        // target code idx 2 DPL=0
        let code0 = mk_seg_desc(0x6000, 0xFFFF, false, 0b1010, true, 0, true, false, true, false);
        write_desc(&mut mem, gdtr.base, 2, code0);
        // TSS idx 6 with ESP0=0x8000, SS0=5<<3; data idx 5 DPL=0
        let data0 = mk_seg_desc(0x7000, 0xFFFF, false, 0b0010, true, 0, true, false, true, false);
        write_desc(&mut mem, gdtr.base, 5, data0);
        let tss_base = 0x3000u64;
        mem.write(tss_base + 0x04, &0x8000u32.to_le_bytes()).unwrap();
        mem.write(tss_base + 0x08, &((5u16<<3).to_le_bytes())).unwrap();
        let tss_desc = mk_seg_desc(tss_base as u32, 0x0067, false, 0b1001, false, 0, true, false, true, false);
        write_desc(&mut mem, gdtr.base, 6, tss_desc);

        // Gate idx 1 to CS=2, present, DPL=3 (allow CPL=3)
        let mut gate_ok = [0u8;8];
        let off = 0x2222_0000u32;
        gate_ok[0] = (off & 0xFF) as u8; gate_ok[1] = ((off>>8)&0xFF) as u8;
        gate_ok[2] = ((2u16<<3) & 0xFF) as u8; gate_ok[3] = (((2u16<<3)>>8)&0xFF) as u8;
        gate_ok[4] = 0; gate_ok[5] = 0x80 | 0x0E | (3<<5); // interrupt gate 32, P=1, DPL=3
        gate_ok[6] = ((off>>16)&0xFF) as u8; gate_ok[7] = ((off>>24)&0xFF) as u8;
        write_desc(&mut mem, gdtr.base, 1, gate_ok);

        // Gate idx 3 with DPL=2 (should fail for CPL=3 & RPL=3)
        let mut gate_bad = gate_ok; gate_bad[5] = 0x80 | 0x0E | (2<<5);
        write_desc(&mut mem, gdtr.base, 3, gate_bad);

        let mut cpu = Cpu::new();
        cpu.gdtr = gdtr;
        // current CS idx 4 (CPL=3)
        let mut cs_flags = DescriptorFlags::TYPE | DescriptorFlags::EXEC | DescriptorFlags::PRESENT;
        cs_flags = DescriptorFlags::from_bits_retain(cs_flags.bits() | (0b11 << 5));
        cpu.segs.set(SegReg::CS, SegmentSelector((4<<3)|3), SegmentCache { base: 0, limit: 0xFFFF, flags: cs_flags, valid: true });
        super::super::segments::instr_ltr(&mut cpu, &mut mem, SegmentSelector(6<<3)).unwrap();
        cpu.segs.set(SegReg::SS, SegmentSelector((7<<3)|3), SegmentCache { base: 0, limit: 0xFFFF, flags: DescriptorFlags::TYPE | DescriptorFlags::RW | DescriptorFlags::PRESENT | DescriptorFlags::DB, valid: true });

        // DPL=2 gate should fault (#GP)
        let err = cpu.exec_jmp_gate32(&mut mem, SegmentSelector((3<<3)|3)).unwrap_err();
        assert_eq!(err.vector, crate::exceptions::Vector::GP);

        // DPL=3 gate succeeds; ring change to 0 and SS loaded from TSS
        cpu.exec_jmp_gate32(&mut mem, SegmentSelector((1<<3)|3)).unwrap();
        assert_eq!(cpu.current_cpl(), 0);
        let (ss_sel, _ss_cache) = cpu.segs.get(SegReg::SS);
        assert_eq!(ss_sel.index(), 5);
        let (cs_sel, _cs_cache) = cpu.segs.get(SegReg::CS);
        assert_eq!(cs_sel.index(), 2);
    }

    #[test]
    fn far_call32_code_conforming_vs_nonconforming_checks() {
        let mut mem = FlatMem::new(0x20000);
        let gdtr = DescriptorTableReg { base: 0x1000, limit: 0x00FF };
        // Non-conforming code DPL=3 (type=1010), conforming readable code DPL=2 (type=1110)
        let code_nc3 = mk_seg_desc(0x4000, 0xFFFF, false, 0b1010, true, 3, true, false, true, false);
        let code_c2  = mk_seg_desc(0x5000, 0xFFFF, false, 0b1110, true, 2, true, false, true, false);
        write_desc(&mut mem, gdtr.base, 2, code_nc3);
        write_desc(&mut mem, gdtr.base, 3, code_c2);
        let mut cpu = Cpu::new();
        cpu.gdtr = gdtr;
        // CPL=3 via CS
        let mut cs_flags = DescriptorFlags::TYPE | DescriptorFlags::EXEC | DescriptorFlags::PRESENT;
        cs_flags = DescriptorFlags::from_bits_retain(cs_flags.bits() | (0b11 << 5));
        cpu.segs.set(SegReg::CS, SegmentSelector((4<<3)|3), SegmentCache { base: 0, limit: 0xFFFF, flags: cs_flags, valid: true });

        // Direct far CALL to nonconforming DPL=3, RPL<=CPL OK
        cpu.exec_far_call32_code(&mut mem, SegmentSelector((2<<3)|3), 0x1000).unwrap();
        // Direct far CALL to conforming DPL=2 is also allowed (no CPL change)
        // Reset return stack to avoid underflow in this simple test
        cpu.segs.set(SegReg::SS, SegmentSelector((5<<3)|3), SegmentCache { base: 0, limit: 0xFFFF, flags: DescriptorFlags::TYPE | DescriptorFlags::RW | DescriptorFlags::PRESENT | DescriptorFlags::DB, valid: true });
        cpu.regs.set32(Gpr::RSP, 0x9000);
        cpu.exec_far_call32_code(&mut mem, SegmentSelector((3<<3)|3), 0x2000).unwrap();

        // Nonconforming with DPL lower than CPL should be rejected
        let code_nc2 = mk_seg_desc(0x6000, 0xFFFF, false, 0b1010, true, 2, true, false, true, false);
        write_desc(&mut mem, gdtr.base, 6, code_nc2);
        let err = cpu.exec_far_call32_code(&mut mem, SegmentSelector((6<<3)|3), 0x3000).unwrap_err();
        assert_eq!(err.vector, crate::exceptions::Vector::GP);
    }

    #[test]
    fn call_gate32_param_copy_2dw() {
        let mut mem = FlatMem::new(0x80000);
        let gdtr = DescriptorTableReg { base: 0x1000, limit: 0x00FF };
        // target code idx 2 DPL=0, 32-bit (DB=1)
        let code0 = mk_seg_desc(0x5000, 0xFFFF, false, 0b1010, true, 0, true, false, true, false);
        write_desc(&mut mem, gdtr.base, 2, code0);
        // data idx 5 DPL=0 for SS0
        let data0 = mk_seg_desc(0x6000, 0xFFFF, false, 0b0010, true, 0, true, false, true, false);
        write_desc(&mut mem, gdtr.base, 5, data0);
        // TSS idx 6 with ESP0=0x8000, SS0=5<<3
        let tss_base = 0x3000u64;
        mem.write(tss_base + 0x04, &0x8000u32.to_le_bytes()).unwrap();
        mem.write(tss_base + 0x08, &((5u16<<3).to_le_bytes())).unwrap();
        let tss_desc = mk_seg_desc(tss_base as u32, 0x0067, false, 0b1001, false, 0, true, false, true, false);
        write_desc(&mut mem, gdtr.base, 6, tss_desc);
        // gate idx 1 to CS=2 with param_count=2 doublewords (hardware interprets as words, DB=1 implies 4-byte units)
        let mut raw = [0u8;8];
        let off = 0x4321_0000u32;
        raw[0] = (off & 0xFF) as u8; raw[1] = ((off>>8)&0xFF) as u8;
        raw[2] = ( (2u16<<3) & 0xFF) as u8; raw[3] = (((2u16<<3)>>8)&0xFF) as u8;
        raw[4] = 0x02; // param_count = 2
        raw[5] = 0x80 | 0x0C | (3<<5); // present, call gate 32, DPL=3
        raw[6] = ((off>>16)&0xFF) as u8; raw[7] = ((off>>24)&0xFF) as u8;
        write_desc(&mut mem, gdtr.base, 1, raw);

        let mut cpu = Cpu::new();
        cpu.gdtr = gdtr;
        // current CS idx 4 (CPL=3)
        let mut cs_flags = DescriptorFlags::TYPE | DescriptorFlags::EXEC | DescriptorFlags::PRESENT;
        cs_flags = DescriptorFlags::from_bits_retain(cs_flags.bits() | (0b11 << 5));
        cpu.segs.set(SegReg::CS, SegmentSelector((4<<3)|3), SegmentCache { base: 0, limit: 0xFFFF, flags: cs_flags, valid: true });
        super::super::segments::instr_ltr(&mut cpu, &mut mem, SegmentSelector(6<<3)).unwrap();
        // Caller SS (ring 3) and two parameters on caller stack at ESP
        cpu.segs.set(SegReg::SS, SegmentSelector((7<<3)|3), SegmentCache { base: 0, limit: 0xFFFF, flags: DescriptorFlags::TYPE | DescriptorFlags::RW | DescriptorFlags::PRESENT | DescriptorFlags::DB, valid: true });
        cpu.regs.set32(Gpr::RSP, 0x9000);
        let p0 = 0x1111_2222u32;
        let p1 = 0x3333_4444u32;
        mem.write(0x9000, &p0.to_le_bytes()).unwrap();
        mem.write(0x9004, &p1.to_le_bytes()).unwrap();
        cpu.regs.rip = 0xAAAA;

        cpu.exec_call_gate32(&mut mem, SegmentSelector((1<<3)|3)).unwrap();
        // New stack should have return pushed at 0x7FFA..0x7FFF and parameters copied at 0x8000 and 0x8004
        let (_ss_sel, ss_cache) = cpu.segs.get(SegReg::SS);
        let rsp = cpu.regs.get32(Gpr::RSP);
        assert_eq!(rsp, 0x8000 - 6);
        let mut b4 = [0u8;4];
        mem.read(ss_cache.base + 0x8000, &mut b4).unwrap();
        assert_eq!(u32::from_le_bytes(b4), p0);
        mem.read(ss_cache.base + 0x8004, &mut b4).unwrap();
        assert_eq!(u32::from_le_bytes(b4), p1);
    }

    #[test]
    fn call_gate16_param_copy_2w() {
        let mut mem = FlatMem::new(0x80000);
        let gdtr = DescriptorTableReg { base: 0x1000, limit: 0x00FF };
        // target 16-bit code idx 2 DPL=0 (DB=0)
        let code0_16 = mk_seg_desc(0x7000, 0xFFFF, false, 0b1010, true, 0, true, false, false, false);
        write_desc(&mut mem, gdtr.base, 2, code0_16);
        // data idx 5 DPL=0 for SS0
        let data0 = mk_seg_desc(0x6000, 0xFFFF, false, 0b0010, true, 0, true, false, true, false);
        write_desc(&mut mem, gdtr.base, 5, data0);
        // TSS idx 6 with ESP0=0x8000, SS0=5<<3
        let tss_base = 0x3000u64;
        mem.write(tss_base + 0x04, &0x8000u32.to_le_bytes()).unwrap();
        mem.write(tss_base + 0x08, &((5u16<<3).to_le_bytes())).unwrap();
        let tss_desc = mk_seg_desc(tss_base as u32, 0x0067, false, 0b1001, false, 0, true, false, true, false);
        write_desc(&mut mem, gdtr.base, 6, tss_desc);
        // 16-bit call gate idx 1 to CS=2 with param_count=2 words
        let mut raw = [0u8;8];
        let off16 = 0x3456u16;
        raw[0] = (off16 & 0xFF) as u8; raw[1] = ((off16>>8)&0xFF) as u8;
        raw[2] = ( (2u16<<3) & 0xFF) as u8; raw[3] = (((2u16<<3)>>8)&0xFF) as u8;
        raw[4] = 0x02; // param_count = 2 (words)
        raw[5] = 0x80 | 0x04 | (3<<5); // present, call gate 16, DPL=3
        raw[6] = 0; raw[7] = 0; // high offset bits unused for 16-bit
        write_desc(&mut mem, gdtr.base, 1, raw);

        let mut cpu = Cpu::new();
        cpu.gdtr = gdtr;
        // current CS idx 4 (CPL=3)
        let mut cs_flags = DescriptorFlags::TYPE | DescriptorFlags::EXEC | DescriptorFlags::PRESENT;
        cs_flags = DescriptorFlags::from_bits_retain(cs_flags.bits() | (0b11 << 5));
        cpu.segs.set(SegReg::CS, SegmentSelector((4<<3)|3), SegmentCache { base: 0, limit: 0xFFFF, flags: cs_flags, valid: true });
        super::super::segments::instr_ltr(&mut cpu, &mut mem, SegmentSelector(6<<3)).unwrap();
        // Caller SS (ring 3) and two 16-bit parameters on caller stack at SP
        cpu.segs.set(SegReg::SS, SegmentSelector((7<<3)|3), SegmentCache { base: 0, limit: 0xFFFF, flags: DescriptorFlags::TYPE | DescriptorFlags::RW | DescriptorFlags::PRESENT, valid: true });
        cpu.regs.set32(Gpr::RSP, 0x9000);
        let p0 = 0x1111u16;
        let p1 = 0x2222u16;
        mem.write(0x9000, &p0.to_le_bytes()).unwrap();
        mem.write(0x9002, &p1.to_le_bytes()).unwrap();
        cpu.regs.rip = 0x0100;

        cpu.exec_call_gate16(&mut mem, SegmentSelector((1<<3)|3)).unwrap();
        // New stack should have return pushed (4 bytes total), parameters at new_esp..new_esp+2
        let (_ss_sel, ss_cache) = cpu.segs.get(SegReg::SS);
        let rsp = cpu.regs.get32(Gpr::RSP);
        assert_eq!(rsp, 0x8000 - 4);
        let mut b2 = [0u8;2];
        mem.read(ss_cache.base + 0x8000, &mut b2).unwrap();
        assert_eq!(u16::from_le_bytes(b2), p0);
        mem.read(ss_cache.base + 0x8002, &mut b2).unwrap();
        assert_eq!(u16::from_le_bytes(b2), p1);
        // Target loaded
        let (cs_sel2, _cs_cache2) = cpu.segs.get(SegReg::CS);
        assert_eq!(cs_sel2.index(), 2);
        assert_eq!(cpu.regs.rip as u32, off16 as u32);
    }

    #[test]
    fn iret32_same_ring_frame_size() {
        let mut mem = FlatMem::new(0x20000);
        let mut cpu = Cpu::new();
        // Prepare GDT with code descriptor at index 1 (CPL=3) and set GDTR
        let gdtr = DescriptorTableReg { base: 0x1000, limit: 0x00FF };
        let code3 = mk_seg_desc(0x0, 0xFFFFF, true, 0b1010, true, 3, true, false, true, false);
        write_desc(&mut mem, gdtr.base, 1, code3);
        cpu.gdtr = gdtr;
        // CS with CPL=3; flat code and SS
        let cs_flags = DescriptorFlags::from_bits_retain((DescriptorFlags::TYPE | DescriptorFlags::EXEC | DescriptorFlags::PRESENT).bits() | (0b11<<5));
        let ss_flags = DescriptorFlags::TYPE | DescriptorFlags::RW | DescriptorFlags::PRESENT | DescriptorFlags::DB;
        cpu.segs.set(SegReg::CS, SegmentSelector((1<<3)|3), SegmentCache { base: 0, limit: 0xFFFFF, flags: cs_flags, valid: true });
        cpu.segs.set(SegReg::SS, SegmentSelector((2<<3)|3), SegmentCache { base: 0, limit: 0xFFFFF, flags: ss_flags, valid: true });
        // Prepare stack at ESP with EIP, CS, EFLAGS
        cpu.regs.set32(Gpr::RSP, 0x7000);
        mem.write(0x7000, &0xDEAD_BEEFu32.to_le_bytes()).unwrap();
        mem.write(0x7000 + 4, &(((1u16<<3)|3).to_le_bytes())).unwrap();
        mem.write(0x7000 + 6, &0x0000_0202u32.to_le_bytes()).unwrap();
        cpu.exec_iret32(&mem).unwrap();
        assert_eq!(cpu.regs.rip as u32, 0xDEAD_BEEF);
        assert_eq!(cpu.regs.get32(Gpr::RSP), 0x7000 + 10);
    }

    #[test]
    fn retf32_same_ring_imm_adjust() {
        let mut mem = FlatMem::new(0x20000);
        let mut cpu = Cpu::new();
        // GDT with code descriptor at index 1
        let gdtr = DescriptorTableReg { base: 0x1000, limit: 0x00FF };
        let code3 = mk_seg_desc(0x0, 0xFFFFF, true, 0b1010, true, 3, true, false, true, false);
        write_desc(&mut mem, gdtr.base, 1, code3);
        cpu.gdtr = gdtr;
        let cs_flags = DescriptorFlags::from_bits_retain((DescriptorFlags::TYPE | DescriptorFlags::EXEC | DescriptorFlags::PRESENT).bits() | (0b11<<5));
        let ss_flags = DescriptorFlags::TYPE | DescriptorFlags::RW | DescriptorFlags::PRESENT | DescriptorFlags::DB;
        cpu.segs.set(SegReg::CS, SegmentSelector((1<<3)|3), SegmentCache { base: 0, limit: 0xFFFFF, flags: cs_flags, valid: true });
        cpu.segs.set(SegReg::SS, SegmentSelector((2<<3)|3), SegmentCache { base: 0, limit: 0xFFFFF, flags: ss_flags, valid: true });
        cpu.regs.set32(Gpr::RSP, 0x7000);
        mem.write(0x7000, &0xCAFEBABEu32.to_le_bytes()).unwrap();
        mem.write(0x7000 + 4, &(((1u16<<3)|3).to_le_bytes())).unwrap();
        cpu.exec_retf32(&mem, 8).unwrap();
        assert_eq!(cpu.regs.rip as u32, 0xCAFEBABE);
        assert_eq!(cpu.regs.get32(Gpr::RSP), 0x7000 + 6 + 8);
    }

    #[test]
    fn iret32_ring_change_to_user() {
        let mut mem = FlatMem::new(0x40000);
        let mut cpu = Cpu::new();
        // GDT with code descriptor at index 3 (DPL=3) and user data at 5 (DPL=3)
        let gdtr = DescriptorTableReg { base: 0x1000, limit: 0x00FF };
        let code3 = mk_seg_desc(0x0, 0xFFFFF, true, 0b1010, true, 3, true, false, true, false);
        let data3 = mk_seg_desc(0x0, 0xFFFFF, true, 0b0010, true, 3, true, false, true, false);
        write_desc(&mut mem, gdtr.base, 3, code3);
        write_desc(&mut mem, gdtr.base, 5, data3);
        cpu.gdtr = gdtr;
        // Current CPL=0 (kernel)
        let cs0 = DescriptorFlags::from_bits_retain((DescriptorFlags::TYPE | DescriptorFlags::EXEC | DescriptorFlags::PRESENT).bits() | (0b00<<5));
        let ss0 = DescriptorFlags::TYPE | DescriptorFlags::RW | DescriptorFlags::PRESENT | DescriptorFlags::DB;
        cpu.segs.set(SegReg::CS, SegmentSelector((1<<3)|0), SegmentCache { base: 0, limit: 0xFFFFF, flags: cs0, valid: true });
        cpu.segs.set(SegReg::SS, SegmentSelector((2<<3)|0), SegmentCache { base: 0, limit: 0xFFFFF, flags: ss0, valid: true });
        // Prepare kernel stack: EIP, CS(user), EFLAGS, ESP(user), SS(user)
        cpu.regs.set32(Gpr::RSP, 0x7000);
        let target_eip = 0x1234_5678u32;
        let user_cs: u16 = ((3u16<<3) | 3);
        let user_ss: u16 = ((5u16<<3) | 3);
        let user_esp: u32 = 0x8000;
        mem.write(0x7000, &target_eip.to_le_bytes()).unwrap();
        mem.write(0x7000 + 4, &user_cs.to_le_bytes()).unwrap();
        mem.write(0x7000 + 6, &0x0000_0202u32.to_le_bytes()).unwrap();
        mem.write(0x7000 + 10, &user_esp.to_le_bytes()).unwrap();
        mem.write(0x7000 + 14, &user_ss.to_le_bytes()).unwrap();
        cpu.exec_iret32(&mem).unwrap();
        // Now at CPL=3 with new SS:ESP loaded
        assert_eq!(cpu.current_cpl(), 3);
        let (ss_sel, _ss_cache) = cpu.segs.get(SegReg::SS);
        assert_eq!(ss_sel.index(), 5);
        assert_eq!(cpu.regs.get32(Gpr::RSP), user_esp);
        assert_eq!(cpu.regs.rip as u32, target_eip);
    }

    #[test]
    fn retf32_ring_change_to_user_with_imm() {
        let mut mem = FlatMem::new(0x40000);
        let mut cpu = Cpu::new();
        // GDT with code descriptor at index 3 (DPL=3) and user data at 5 (DPL=3)
        let gdtr = DescriptorTableReg { base: 0x1000, limit: 0x00FF };
        let code3 = mk_seg_desc(0x0, 0xFFFFF, true, 0b1010, true, 3, true, false, true, false);
        let data3 = mk_seg_desc(0x0, 0xFFFFF, true, 0b0010, true, 3, true, false, true, false);
        write_desc(&mut mem, gdtr.base, 3, code3);
        write_desc(&mut mem, gdtr.base, 5, data3);
        cpu.gdtr = gdtr;
        // Current CPL=0 (kernel)
        let cs0 = DescriptorFlags::from_bits_retain((DescriptorFlags::TYPE | DescriptorFlags::EXEC | DescriptorFlags::PRESENT).bits() | (0b00<<5));
        let ss0 = DescriptorFlags::TYPE | DescriptorFlags::RW | DescriptorFlags::PRESENT | DescriptorFlags::DB;
        cpu.segs.set(SegReg::CS, SegmentSelector((1<<3)|0), SegmentCache { base: 0, limit: 0xFFFFF, flags: cs0, valid: true });
        cpu.segs.set(SegReg::SS, SegmentSelector((2<<3)|0), SegmentCache { base: 0, limit: 0xFFFFF, flags: ss0, valid: true });
        // Prepare frame: EIP, CS(user), ESP(user), SS(user)
        cpu.regs.set32(Gpr::RSP, 0x7000);
        let target_eip = 0xCAFEBABEu32;
        let user_cs: u16 = ((3u16<<3) | 3);
        let user_ss: u16 = ((5u16<<3) | 3);
        let user_esp: u32 = 0x9000;
        mem.write(0x7000, &target_eip.to_le_bytes()).unwrap();
        mem.write(0x7000 + 4, &user_cs.to_le_bytes()).unwrap();
        mem.write(0x7000 + 6, &user_esp.to_le_bytes()).unwrap();
        mem.write(0x7000 + 10, &user_ss.to_le_bytes()).unwrap();
        cpu.exec_retf32(&mem, 8).unwrap();
        assert_eq!(cpu.current_cpl(), 3);
        let (ss_sel, _ss_cache) = cpu.segs.get(SegReg::SS);
        assert_eq!(ss_sel.index(), 5);
        // imm16 adjustment applied on destination stack
        assert_eq!(cpu.regs.get32(Gpr::RSP), user_esp + 8);
        assert_eq!(cpu.regs.rip as u32, target_eip);
    }

    #[test]
    fn translate_lin32_4k_and_4m() {
        let mut mem = FlatMem::new(0x200000);
        let mut cpu = Cpu::new();
        // Enable paging + PSE
        cpu.cr0 |= crate::control::Cr0::PG;
        cpu.cr4 |= crate::control::Cr4::PSE;
        // Set CR3 to 0x1000
        cpu.cr3.pml4 = 0x1000;
        // PDE[0] -> PT at 0x2000, P/RW/US
        // PTE[0] -> page at 0x3000, P/RW/US
        // Write tables
        mem.write(0x1000, &0x0000_2000u32.to_le_bytes()).unwrap();
        // set P,RW,US on PDE
        let mut pde = [0u8;4]; mem.read(0x1000, &mut pde).unwrap();
        let mut pde_val = u32::from_le_bytes(pde) | 0b111; mem.write(0x1000, &pde_val.to_le_bytes()).unwrap();
        // PTE
        mem.write(0x2000, &0x0000_3000u32.to_le_bytes()).unwrap();
        let mut pte = [0u8;4]; mem.read(0x2000, &mut pte).unwrap();
        let mut pte_val = u32::from_le_bytes(pte) | 0b111; mem.write(0x2000, &pte_val.to_le_bytes()).unwrap();

        // Translate 0x0000_0004
        let tr = cpu.translate_lin32(&mut mem, 0x0000_0004, false, true, false).unwrap();
        assert_eq!(tr.phys, 0x3004);

        // 4MiB mapping at dir=1 to base=0x0040_0000
        let pde1 = 0x0040_0000u32 | (1<<7) | 0b111; // PS,P,RW,US
        mem.write(0x1000 + 4, &pde1.to_le_bytes()).unwrap();
        let tr2 = cpu.translate_lin32(&mut mem, 0x0040_1000, false, true, false).unwrap();
        assert_eq!(tr2.phys, 0x0040_1000);
    }

    #[test]
    fn tlb_invlpg_behavior() {
        let mut mem = FlatMem::new(0x10000);
        let mut cpu = Cpu::new();
        cpu.cr0 |= crate::control::Cr0::PG;
        cpu.cr3.pml4 = 0x1000;
        // PDE[0] -> PT at 0x2000 P/RW/US; PTE[0] -> 0x3000 P/RW/US
        mem.write(0x1000, &0x0000_2000u32.to_le_bytes()).unwrap();
        let mut v = [0u8;4]; mem.read(0x1000, &mut v).unwrap();
        let mut pde = u32::from_le_bytes(v) | 0b111; mem.write(0x1000, &pde.to_le_bytes()).unwrap();
        mem.write(0x2000, &0x0000_3000u32.to_le_bytes()).unwrap();
        mem.read(0x2000, &mut v).unwrap();
        let mut pte = u32::from_le_bytes(v) | 0b111; mem.write(0x2000, &pte.to_le_bytes()).unwrap();

        // First translation fills TLB
        let tr1 = cpu.translate_lin32(&mut mem, 0x0000_0000, true, true, false).unwrap();
        assert_eq!(tr1.phys, 0x3000);
        // Change PTE to not present
        pte &= !1u32; mem.write(0x2000, &pte.to_le_bytes()).unwrap();
        // With stale TLB, still translates
        let tr2 = cpu.translate_lin32(&mut mem, 0x0000_0000, true, true, false).unwrap();
        assert_eq!(tr2.phys, 0x3000);
        // Invalidate and now translation should fault
        cpu.invlpg(0x0000_0000);
        let pf = cpu.translate_lin32(&mut mem, 0x0000_0000, true, true, false).unwrap_err();
        assert_eq!(pf.kind, mmu_tlb::PageFaultKind::NotPresent);
    }

    #[test]
    fn mem_read_write_with_segmentation_and_paging() {
        let mut mem = FlatMem::new(0x10000);
        let mut cpu = Cpu::new();
        // Set DS as flat data, CPL=3 via CS
        let mut cs_flags = DescriptorFlags::TYPE | DescriptorFlags::EXEC | DescriptorFlags::PRESENT;
        cs_flags = DescriptorFlags::from_bits_retain(cs_flags.bits() | (0b11 << 5));
        cpu.segs.set(SegReg::CS, SegmentSelector((1<<3)|3), SegmentCache { base: 0, limit: 0xFFFFF, flags: cs_flags, valid: true });
        let ds_flags = DescriptorFlags::TYPE | DescriptorFlags::RW | DescriptorFlags::PRESENT | DescriptorFlags::DB;
        cpu.segs.set(SegReg::DS, SegmentSelector((2<<3)|3), SegmentCache { base: 0, limit: 0xFFFFF, flags: ds_flags, valid: true });
        // Enable paging
        cpu.cr0 |= crate::control::Cr0::PG;
        cpu.cr3.pml4 = 0x1000;
        // Map linear 0..4K -> physical 0x3000.., P/RW/US
        mem.write(0x1000, &0x0000_2000u32.to_le_bytes()).unwrap();
        let mut pde = [0u8;4]; mem.read(0x1000, &mut pde).unwrap();
        let pde_val = u32::from_le_bytes(pde) | 0b111; mem.write(0x1000, &pde_val.to_le_bytes()).unwrap();
        mem.write(0x2000, &0x0000_3000u32.to_le_bytes()).unwrap();
        let mut pte = [0u8;4]; mem.read(0x2000, &mut pte).unwrap();
        let pte_val = u32::from_le_bytes(pte) | 0b111; mem.write(0x2000, &pte_val.to_le_bytes()).unwrap();
        // Write and read through DS:0x10
        cpu.mem_write_u8(&mut mem, SegReg::DS, 0x10, 0xAB).unwrap();
        let v = cpu.mem_read_u8(&mut mem, SegReg::DS, 0x10).unwrap();
        assert_eq!(v, 0xAB);
    }
}
