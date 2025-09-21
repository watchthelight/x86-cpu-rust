use serde::{Deserialize, Serialize};
use crate::exceptions::{Exception, Vector};
use crate::memory::Memory;
use crate::cpu::Cpu;

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SegmentSelector(pub u16);

impl SegmentSelector {
    pub fn index(self) -> u16 { (self.0 >> 3) & 0x1FFF }
    pub fn ti(self) -> bool { (self.0 & 0x4) != 0 }
    pub fn rpl(self) -> u8 { (self.0 & 0x3) as u8 }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SegmentCache {
    pub base: u64,
    pub limit: u32,
    pub flags: DescriptorFlags,
    pub valid: bool,
}

bitflags::bitflags! {
    #[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
    pub struct DescriptorFlags: u32 {
        const A = 1<<0;      // Accessed
        const RW = 1<<1;     // Readable/Writable
        const DC = 1<<2;     // Direction/Conforming
        const EXEC = 1<<3;   // Executable
        const TYPE = 1<<4;   // Descriptor type (1=code/data)
        const DPL0 = 1<<5;   // DPL low bit
        const DPL1 = 1<<6;   // DPL high bit
        const PRESENT = 1<<7;// Present
        const AVL = 1<<12;   // Available for system software
        const L = 1<<13;     // 64-bit code segment
        const DB = 1<<14;    // Default operation size (0=16,1=32)
        const G = 1<<15;     // Granularity (0=byte,1=4KiB)
    }
}

impl DescriptorFlags {
    pub fn dpl(&self) -> u8 {
        (((self.bits() >> 5) & 1) | (((self.bits() >> 6) & 1) << 1)) as u8
    }
    pub fn present(&self) -> bool { self.contains(DescriptorFlags::PRESENT) }
    pub fn is_code(&self) -> bool { self.contains(DescriptorFlags::EXEC) }
    pub fn is_data(&self) -> bool { !self.is_code() }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SegReg { CS, DS, ES, FS, GS, SS }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegState {
    pub cs: (SegmentSelector, SegmentCache),
    pub ds: (SegmentSelector, SegmentCache),
    pub es: (SegmentSelector, SegmentCache),
    pub fs: (SegmentSelector, SegmentCache),
    pub gs: (SegmentSelector, SegmentCache),
    pub ss: (SegmentSelector, SegmentCache),
}

impl Default for SegState {
    fn default() -> Self {
        let null = (SegmentSelector(0), SegmentCache::default());
        Self { cs: null, ds: null, es: null, fs: null, gs: null, ss: null }
    }
}

impl SegState {
    pub fn get(&self, r: SegReg) -> (SegmentSelector, SegmentCache) {
        match r {
            SegReg::CS => self.cs,
            SegReg::DS => self.ds,
            SegReg::ES => self.es,
            SegReg::FS => self.fs,
            SegReg::GS => self.gs,
            SegReg::SS => self.ss,
        }
    }
    pub fn set(&mut self, r: SegReg, sel: SegmentSelector, cache: SegmentCache) {
        match r {
            SegReg::CS => self.cs = (sel, cache),
            SegReg::DS => self.ds = (sel, cache),
            SegReg::ES => self.es = (sel, cache),
            SegReg::FS => self.fs = (sel, cache),
            SegReg::GS => self.gs = (sel, cache),
            SegReg::SS => self.ss = (sel, cache),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DescriptorTableReg {
    pub base: u64,
    pub limit: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SystemDescType {
    Ldt = 0b0010,
    TssAvail16 = 0b0001,
    TssBusy16 = 0b0011,
    CallGate16 = 0b0100,
    TaskGate = 0b0101,
    InterruptGate16 = 0b0110,
    TrapGate16 = 0b0111,
    TssAvail32 = 0b1001,
    TssBusy32 = 0b1011,
    CallGate32 = 0b1100,
    InterruptGate32 = 0b1110,
    TrapGate32 = 0b1111,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DescKind { CodeData, System(SystemDescType) }

#[derive(Debug, Clone, Copy)]
struct ParsedDesc {
    base: u64,
    limit: u32,
    flags: DescriptorFlags,
    kind: DescKind,
}

fn parse_descriptor(raw: [u8; 8]) -> ParsedDesc {
    let limit0 = (raw[0] as u32) | ((raw[1] as u32) << 8);
    let base0 = (raw[2] as u32) | ((raw[3] as u32) << 8);
    let base1 = raw[4] as u32;
    let access = raw[5];
    let limit1 = (raw[6] & 0x0F) as u32;
    let flags = (raw[6] & 0xF0) >> 4; // AVL|L|DB|G
    let base2 = raw[7] as u32;

    let limit = (limit0 | (limit1 << 16)) as u32;
    let mut base = base0 | (base1 << 16) | (base2 << 24);
    let s = (access >> 4) & 1; // 1=code/data, 0=system
    let typ = access & 0x0F; // low 4 bits
    let dpl = (access >> 5) & 0x3;
    let present = ((access >> 7) & 1) != 0;
    let avl = (flags & 0x1) != 0;
    let long = (flags & 0x2) != 0;
    let db = (flags & 0x4) != 0;
    let gran = (flags & 0x8) != 0; // 1=4K

    // For 64-bit system descriptors (TSS/LDT), an upper 32-bit base exists in the next 8 bytes.
    // The caller is responsible for fetching if needed. For now, base is 32-bit.

    let mut df = DescriptorFlags::empty();
    if (typ & 0x1) != 0 { df |= DescriptorFlags::A; }
    if (typ & 0x2) != 0 { df |= DescriptorFlags::RW; }
    if (typ & 0x4) != 0 { df |= DescriptorFlags::DC; }
    if (typ & 0x8) != 0 { df |= DescriptorFlags::EXEC; }
    if s != 0 { df |= DescriptorFlags::TYPE; }
    if present { df |= DescriptorFlags::PRESENT; }
    if avl { df |= DescriptorFlags::AVL; }
    if long { df |= DescriptorFlags::L; }
    if db { df |= DescriptorFlags::DB; }
    if gran { df |= DescriptorFlags::G; }
    // DPL bits into flags struct (DPL0/DPL1 placeholders)
    if (dpl & 0x1) != 0 { df |= DescriptorFlags::DPL0; }
    if (dpl & 0x2) != 0 { df |= DescriptorFlags::DPL1; }

    let kind = if s != 0 {
        DescKind::CodeData
    } else {
        // Map system type
        let sys = match typ {
            0b0010 => SystemDescType::Ldt,
            0b0001 => SystemDescType::TssAvail16,
            0b0011 => SystemDescType::TssBusy16,
            0b0100 => SystemDescType::CallGate16,
            0b0101 => SystemDescType::TaskGate,
            0b0110 => SystemDescType::InterruptGate16,
            0b0111 => SystemDescType::TrapGate16,
            0b1001 => SystemDescType::TssAvail32,
            0b1011 => SystemDescType::TssBusy32,
            0b1100 => SystemDescType::CallGate32,
            0b1110 => SystemDescType::InterruptGate32,
            0b1111 => SystemDescType::TrapGate32,
            _ => SystemDescType::Ldt, // placeholder; invalid types to be rejected by caller
        };
        DescKind::System(sys)
    };

    let limit_final = if gran { (limit << 12) | 0xFFF } else { limit };
    ParsedDesc { base: base as u64, limit: limit_final, flags: df, kind }
}

fn read_descriptor(mem: &dyn Memory, table: DescriptorTableReg, sel: SegmentSelector) -> Result<ParsedDesc, Exception> {
    let index = sel.index() as u64;
    let offset = index * 8;
    let end = offset + 7;
    if end as u16 > table.limit { return Err(Exception::new(Vector::GP, Some(sel.0 as u32))); }
    let addr = table.base.wrapping_add(offset);
    let mut buf = [0u8; 8];
    mem.read(addr, &mut buf).map_err(|_| Exception::new(Vector::GP, Some(sel.0 as u32)))?;
    Ok(parse_descriptor(buf))
}

fn read_descriptor_raw(mem: &dyn Memory, table: DescriptorTableReg, sel: SegmentSelector) -> Result<[u8;8], Exception> {
    let index = sel.index() as u64;
    let offset = index * 8;
    let end = offset + 7;
    if end as u16 > table.limit { return Err(Exception::new(Vector::GP, Some(sel.0 as u32))); }
    let addr = table.base.wrapping_add(offset);
    let mut buf = [0u8; 8];
    mem.read(addr, &mut buf).map_err(|_| Exception::new(Vector::GP, Some(sel.0 as u32)))?;
    Ok(buf)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GateKind { Call16, Call32, Interrupt16, Interrupt32, Trap16, Trap32, TaskGate }

#[derive(Debug, Clone, Copy)]
struct GateDesc { kind: GateKind, selector: SegmentSelector, offset: u32, dpl: u8, present: bool, param_count: u8 }

fn read_gate(mem: &dyn Memory, table: DescriptorTableReg, sel: SegmentSelector) -> Result<GateDesc, Exception> {
    let raw = read_descriptor_raw(mem, table, sel)?;
    let typ = raw[5] & 0x0F;
    let s = (raw[5] >> 4) & 1;
    if s != 0 { return Err(Exception::new(Vector::GP, Some(sel.0 as u32))); }
    let dpl = (raw[5] >> 5) & 0x3;
    let present = ((raw[5] >> 7) & 1) != 0;
    let selector = SegmentSelector(((raw[3] as u16) << 8) | raw[2] as u16);
    let param_count = raw[4] & 0x1F; // for call gates
    let kind = match typ {
        0x4 => GateKind::Call16,
        0xC => GateKind::Call32,
        0x6 => GateKind::Interrupt16,
        0xE => GateKind::Interrupt32,
        0x7 => GateKind::Trap16,
        0xF => GateKind::Trap32,
        0x5 => GateKind::TaskGate,
        _ => return Err(Exception::new(Vector::GP, Some(sel.0 as u32))),
    };
    let offset = match kind {
        GateKind::Call32 | GateKind::Interrupt32 | GateKind::Trap32 => {
            (raw[0] as u32) | ((raw[1] as u32) << 8) | ((raw[6] as u32) << 16) | ((raw[7] as u32) << 24)
        }
        _ => { (raw[0] as u32) | ((raw[1] as u32) << 8) }
    };
    Ok(GateDesc { kind, selector, offset, dpl, present, param_count })
}

fn write_descriptor_raw(mem: &mut dyn Memory, table: DescriptorTableReg, sel: SegmentSelector, buf: &[u8;8]) -> Result<(), Exception> {
    let index = sel.index() as u64;
    let offset = index * 8;
    let end = offset + 7;
    if end as u16 > table.limit { return Err(Exception::new(Vector::GP, Some(sel.0 as u32))); }
    let addr = table.base.wrapping_add(offset);
    mem.write(addr, buf).map_err(|_| Exception::new(Vector::GP, Some(sel.0 as u32)))
}

pub fn load_data_segment(mem: &dyn Memory, gdtr: DescriptorTableReg, ldtr: Option<(SegmentSelector, SegmentCache)>, seg: SegReg, sel: SegmentSelector, cpl: u8) -> Result<(SegmentSelector, SegmentCache), Exception> {
    // Loading null selector clears segment (except SS which #GP(0))
    if sel.index() == 0 {
        if matches!(seg, SegReg::SS) {
            return Err(Exception::new(Vector::GP, Some(0)));
        }
        return Ok((SegmentSelector(0), SegmentCache { base: 0, limit: 0, flags: DescriptorFlags::empty(), valid: false }));
    }
    let table = if sel.ti() {
        // LDT
        let (ldt_sel, ldt_cache) = ldtr.ok_or_else(|| Exception::new(Vector::GP, Some(sel.0 as u32)))?;
        if !ldt_cache.valid || !ldt_cache.flags.present() { return Err(Exception::new(Vector::GP, Some(sel.0 as u32))); }
        DescriptorTableReg { base: ldt_cache.base, limit: (ldt_cache.limit & 0xFFFF) as u16 }
    } else { gdtr };

    let desc = read_descriptor(mem, table, sel)?;
    if !desc.flags.present() {
        // Loading a not-present stack segment uses #SS; others use #NP
        let vec = if matches!(seg, SegReg::SS) { Vector::SS } else { Vector::NP };
        return Err(Exception::new(vec, Some(sel.0 as u32)));
    }
    // Must be data or readable code for DS/ES/FS/GS; for SS must be writable data
    match seg {
        SegReg::SS => {
            // Must be writable data segment; RPL must equal CPL; DPL must equal CPL
            if desc.kind != DescKind::CodeData || desc.flags.is_code() || !desc.flags.contains(DescriptorFlags::RW) {
                return Err(Exception::new(Vector::GP, Some(sel.0 as u32)));
            }
            if sel.rpl() != cpl { return Err(Exception::new(Vector::GP, Some(sel.0 as u32))); }
            if desc.flags.dpl() != cpl { return Err(Exception::new(Vector::GP, Some(sel.0 as u32))); }
        }
        _ => {
            if desc.kind != DescKind::CodeData { return Err(Exception::new(Vector::GP, Some(sel.0 as u32))); }
            let eff = core::cmp::max(cpl, sel.rpl());
            if desc.flags.is_code() {
                // Only non-conforming, readable code segments are allowed in DS/ES/FS/GS
                if desc.flags.contains(DescriptorFlags::DC) { return Err(Exception::new(Vector::GP, Some(sel.0 as u32))); }
                // Code segment usable for reading data only if readable and DPL >= max(CPL,RPL)
                if !desc.flags.contains(DescriptorFlags::RW) { return Err(Exception::new(Vector::GP, Some(sel.0 as u32))); }
                if desc.flags.dpl() < eff { return Err(Exception::new(Vector::GP, Some(sel.0 as u32))); }
            } else {
                // Data segment: DPL >= max(CPL,RPL)
                if desc.flags.dpl() < eff { return Err(Exception::new(Vector::GP, Some(sel.0 as u32))); }
            }
        }
    }
    let cache = SegmentCache { base: desc.base, limit: desc.limit, flags: desc.flags, valid: true };
    Ok((sel, cache))
}

pub fn load_cs_same_priv(mem: &dyn Memory, gdtr: DescriptorTableReg, ldtr: Option<(SegmentSelector, SegmentCache)>, current_cpl: u8, sel: SegmentSelector) -> Result<(SegmentSelector, SegmentCache, u8), Exception> {
    // Only same-privilege far JMP/CALL, non-conforming requires DPL==CPL and RPL<=CPL
    if sel.index() == 0 { return Err(Exception::new(Vector::GP, Some(0))); }
    let table = if sel.ti() {
        let (_, ldt_cache) = ldtr.ok_or_else(|| Exception::new(Vector::GP, Some(sel.0 as u32)))?;
        if !ldt_cache.valid || !ldt_cache.flags.present() { return Err(Exception::new(Vector::GP, Some(sel.0 as u32))); }
        DescriptorTableReg { base: ldt_cache.base, limit: (ldt_cache.limit & 0xFFFF) as u16 }
    } else { gdtr };
    let desc = read_descriptor(mem, table, sel)?;
    if !desc.flags.present() { return Err(Exception::new(Vector::NP, Some(sel.0 as u32))); }
    if desc.kind != DescKind::CodeData || !desc.flags.is_code() { return Err(Exception::new(Vector::GP, Some(sel.0 as u32))); }
    let dpl = desc.flags.dpl();
    let rpl = sel.rpl();
    let conforming = desc.flags.contains(DescriptorFlags::DC);
    if conforming {
        // same or less privileged target; CPL unchanged
        if dpl > current_cpl { return Err(Exception::new(Vector::GP, Some(sel.0 as u32))); }
        let cache = SegmentCache { base: desc.base, limit: desc.limit, flags: desc.flags, valid: true };
        Ok((sel, cache, current_cpl))
    } else {
        if dpl != current_cpl || rpl > current_cpl { return Err(Exception::new(Vector::GP, Some(sel.0 as u32))); }
        let cache = SegmentCache { base: desc.base, limit: desc.limit, flags: desc.flags, valid: true };
        Ok((sel, cache, current_cpl))
    }
}

pub fn load_ldt(mem: &dyn Memory, gdtr: DescriptorTableReg, sel: SegmentSelector) -> Result<(SegmentSelector, SegmentCache), Exception> {
    if sel.index() == 0 {
        // Null selector clears LDTR
        return Ok((SegmentSelector(0), SegmentCache { base: 0, limit: 0, flags: DescriptorFlags::empty(), valid: false }));
    }
    if sel.ti() { return Err(Exception::new(Vector::GP, Some(sel.0 as u32))); }
    let desc = read_descriptor(mem, gdtr, sel)?;
    match desc.kind {
        DescKind::System(SystemDescType::Ldt) => {}
        _ => return Err(Exception::new(Vector::GP, Some(sel.0 as u32))),
    }
    if !desc.flags.present() { return Err(Exception::new(Vector::NP, Some(sel.0 as u32))); }
    let cache = SegmentCache { base: desc.base, limit: desc.limit, flags: desc.flags, valid: true };
    Ok((sel, cache))
}

pub fn load_tr_set_busy(mem: &mut dyn Memory, gdtr: DescriptorTableReg, sel: SegmentSelector) -> Result<(SegmentSelector, SegmentCache), Exception> {
    if sel.index() == 0 { return Err(Exception::new(Vector::GP, Some(0))); }
    if sel.ti() { return Err(Exception::new(Vector::GP, Some(sel.0 as u32))); }
    let raw = read_descriptor_raw(mem, gdtr, sel)?;
    let mut parsed = parse_descriptor(raw);
    // Must be available TSS (16 or 32), not busy
    let is_avail_tss = matches!(parsed.kind, DescKind::System(SystemDescType::TssAvail16 | SystemDescType::TssAvail32));
    let is_busy_tss = matches!(parsed.kind, DescKind::System(SystemDescType::TssBusy16 | SystemDescType::TssBusy32));
    if is_busy_tss { return Err(Exception::new(Vector::GP, Some(sel.0 as u32))); }
    if !is_avail_tss { return Err(Exception::new(Vector::GP, Some(sel.0 as u32))); }
    if !parsed.flags.present() { return Err(Exception::new(Vector::NP, Some(sel.0 as u32))); }
    // Set busy bit in descriptor type (low nibble OR 0b0010)
    let mut new = raw;
    new[5] = (new[5] & 0xF0) | ((new[5] & 0x0F) | 0b0010);
    write_descriptor_raw(mem, gdtr, sel, &new)?;
    // Update parsed kind to busy variant for returned cache flags (semantics unaffected for cache)
    parsed.kind = match parsed.kind {
        DescKind::System(SystemDescType::TssAvail16) => DescKind::System(SystemDescType::TssBusy16),
        DescKind::System(SystemDescType::TssAvail32) => DescKind::System(SystemDescType::TssBusy32),
        other => other,
    };
    let cache = SegmentCache { base: parsed.base, limit: parsed.limit, flags: parsed.flags, valid: true };
    Ok((sel, cache))
}

// Instruction-style helpers
pub fn instr_lgdt(cpu: &mut Cpu, base: u64, limit: u16) {
    cpu.gdtr = DescriptorTableReg { base, limit };
}

pub fn instr_lidt(cpu: &mut Cpu, base: u64, limit: u16) {
    cpu.idtr = DescriptorTableReg { base, limit };
}

pub fn instr_sgdt(cpu: &Cpu) -> DescriptorTableReg { cpu.gdtr }
pub fn instr_sidt(cpu: &Cpu) -> DescriptorTableReg { cpu.idtr }

pub fn instr_lldt(cpu: &mut Cpu, mem: &dyn Memory, sel: SegmentSelector) -> Result<(), Exception> {
    let (s, c) = load_ldt(mem, cpu.gdtr, sel)?;
    cpu.ldtr = (s, c);
    Ok(())
}

pub fn instr_ltr(cpu: &mut Cpu, mem: &mut dyn Memory, sel: SegmentSelector) -> Result<(), Exception> {
    let (s, c) = load_tr_set_busy(mem, cpu.gdtr, sel)?;
    cpu.tr = (s, c);
    Ok(())
}

pub fn instr_sldt(cpu: &Cpu) -> SegmentSelector { cpu.ldtr.0 }
pub fn instr_str(cpu: &Cpu) -> SegmentSelector { cpu.tr.0 }

fn ar_from_desc(pd: &ParsedDesc) -> u32 {
    // Access-rights format (per SDM):
    // Bits 0..3: Type (A/RW/DC/EXEC)
    // Bit 4: S (1=code/data)
    // Bits 5..6: DPL
    // Bit 7: Present
    // Bits 8..11: reserved (0)
    // Bit 12: AVL
    // Bit 13: L
    // Bit 14: DB (B bit for data, D bit for code)
    // Bit 15: G
    let mut ar: u32 = 0;
    let f = pd.flags;
    let mut typ: u8 = 0;
    if f.contains(DescriptorFlags::A) { typ |= 1<<0; }
    if f.contains(DescriptorFlags::RW) { typ |= 1<<1; }
    if f.contains(DescriptorFlags::DC) { typ |= 1<<2; }
    if f.contains(DescriptorFlags::EXEC) { typ |= 1<<3; }
    ar |= typ as u32;
    if f.contains(DescriptorFlags::TYPE) { ar |= 1<<4; }
    ar |= ((f.dpl() as u32) & 0x3) << 5;
    if f.contains(DescriptorFlags::PRESENT) { ar |= 1<<7; }
    if f.contains(DescriptorFlags::AVL) { ar |= 1<<12; }
    if f.contains(DescriptorFlags::L) { ar |= 1<<13; }
    if f.contains(DescriptorFlags::DB) { ar |= 1<<14; }
    if f.contains(DescriptorFlags::G) { ar |= 1<<15; }
    ar
}

pub fn lar(mem: &dyn Memory, gdtr: DescriptorTableReg, ldtr: Option<(SegmentSelector, SegmentCache)>, sel: SegmentSelector) -> Result<Option<u32>, Exception> {
    if sel.index() == 0 { return Ok(None); }
    let table = if sel.ti() {
        let (_, ldt_cache) = ldtr.ok_or_else(|| Exception::new(Vector::GP, Some(sel.0 as u32)))?;
        if !ldt_cache.valid || !ldt_cache.flags.present() { return Err(Exception::new(Vector::GP, Some(sel.0 as u32))); }
        DescriptorTableReg { base: ldt_cache.base, limit: (ldt_cache.limit & 0xFFFF) as u16 }
    } else { gdtr };
    let desc = read_descriptor(mem, table, sel)?;
    match desc.kind {
        DescKind::CodeData => Ok(Some(ar_from_desc(&desc))),
        _ => Ok(None),
    }
}

pub fn lsl(mem: &dyn Memory, gdtr: DescriptorTableReg, ldtr: Option<(SegmentSelector, SegmentCache)>, sel: SegmentSelector) -> Result<Option<u32>, Exception> {
    if sel.index() == 0 { return Ok(None); }
    let table = if sel.ti() {
        let (_, ldt_cache) = ldtr.ok_or_else(|| Exception::new(Vector::GP, Some(sel.0 as u32)))?;
        if !ldt_cache.valid || !ldt_cache.flags.present() { return Err(Exception::new(Vector::GP, Some(sel.0 as u32))); }
        DescriptorTableReg { base: ldt_cache.base, limit: (ldt_cache.limit & 0xFFFF) as u16 }
    } else { gdtr };
    let desc = read_descriptor(mem, table, sel)?;
    match desc.kind {
        DescKind::CodeData => Ok(Some(desc.limit)),
        _ => Ok(None),
    }
}

pub fn verr(mem: &dyn Memory, gdtr: DescriptorTableReg, ldtr: Option<(SegmentSelector, SegmentCache)>, cpl: u8, sel: SegmentSelector) -> bool {
    if sel.index() == 0 { return false; }
    let table = if sel.ti() {
        match ldtr {
            Some((_, ldt_cache)) if ldt_cache.valid && ldt_cache.flags.present() => DescriptorTableReg { base: ldt_cache.base, limit: (ldt_cache.limit & 0xFFFF) as u16 },
            _ => return false,
        }
    } else { gdtr };
    let desc = match read_descriptor(mem, table, sel) { Ok(d) => d, Err(_) => return false };
    if !desc.flags.present() { return false; }
    match desc.kind {
        DescKind::CodeData => {
            let dpl = desc.flags.dpl();
            let rpl = sel.rpl();
            if desc.flags.is_code() {
                if !desc.flags.contains(DescriptorFlags::RW) { return false; }
                let conforming = desc.flags.contains(DescriptorFlags::DC);
                if conforming {
                    cpl >= dpl
                } else {
                    (cpl <= dpl) && (rpl <= dpl)
                }
            } else {
                // data segment: readable if privilege check passes
                let eff = core::cmp::max(cpl, rpl);
                eff <= dpl
            }
        }
        _ => false,
    }
}

pub fn verw(mem: &dyn Memory, gdtr: DescriptorTableReg, ldtr: Option<(SegmentSelector, SegmentCache)>, cpl: u8, sel: SegmentSelector) -> bool {
    if sel.index() == 0 { return false; }
    let table = if sel.ti() {
        match ldtr {
            Some((_, ldt_cache)) if ldt_cache.valid && ldt_cache.flags.present() => DescriptorTableReg { base: ldt_cache.base, limit: (ldt_cache.limit & 0xFFFF) as u16 },
            _ => return false,
        }
    } else { gdtr };
    let desc = match read_descriptor(mem, table, sel) { Ok(d) => d, Err(_) => return false };
    if !desc.flags.present() { return false; }
    match desc.kind {
        DescKind::CodeData => {
            if desc.flags.is_code() { return false; }
            if !desc.flags.contains(DescriptorFlags::RW) { return false; }
            let dpl = desc.flags.dpl();
            let rpl = sel.rpl();
            let eff = core::cmp::max(cpl, rpl);
            eff <= dpl
        }
        _ => false,
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CallResolution {
    pub target_sel: SegmentSelector,
    pub target_offset: u32,
    pub target_cache: SegmentCache,
    pub new_cpl: u8,
    pub new_ss: Option<(SegmentSelector, SegmentCache, u32)>,
    pub param_count: u8,
    pub param_unit: u8,
    pub ret_ip_size: u8,
}

pub fn resolve_call_gate(cpu: &Cpu, mem: &dyn Memory, gate_sel: SegmentSelector, current_cpl: u8) -> Result<CallResolution, Exception> {
    // Locate gate
    let table = if gate_sel.ti() {
        let (_, ldt_cache) = cpu.ldtr;
        if !ldt_cache.valid || !ldt_cache.flags.present() { return Err(Exception::new(Vector::GP, Some(gate_sel.0 as u32))); }
        DescriptorTableReg { base: ldt_cache.base, limit: (ldt_cache.limit & 0xFFFF) as u16 }
    } else { cpu.gdtr };
    let gate = read_gate(mem, table, gate_sel)?;
    if !gate.present { return Err(Exception::new(Vector::NP, Some(gate_sel.0 as u32))); }
    // Privilege check for gate itself: max(CPL, RPL) <= DPL(gate)
    let eff = core::cmp::max(current_cpl, gate_sel.rpl());
    if eff > gate.dpl { return Err(Exception::new(Vector::GP, Some(gate_sel.0 as u32))); }

    // Resolve target code descriptor
    let target_table = if gate.selector.ti() {
        let (_, ldt_cache) = cpu.ldtr;
        if !ldt_cache.valid || !ldt_cache.flags.present() { return Err(Exception::new(Vector::GP, Some(gate.selector.0 as u32))); }
        DescriptorTableReg { base: ldt_cache.base, limit: (ldt_cache.limit & 0xFFFF) as u16 }
    } else { cpu.gdtr };
    let tdesc = read_descriptor(mem, target_table, gate.selector)?;
    if !tdesc.flags.present() { return Err(Exception::new(Vector::NP, Some(gate.selector.0 as u32))); }
    if tdesc.kind != DescKind::CodeData || !tdesc.flags.is_code() {
        return Err(Exception::new(Vector::GP, Some(gate.selector.0 as u32)));
    }
    let dpl = tdesc.flags.dpl();
    let conforming = tdesc.flags.contains(DescriptorFlags::DC);
    let mut new_cpl = current_cpl;
    if conforming {
        if dpl > current_cpl { return Err(Exception::new(Vector::GP, Some(gate.selector.0 as u32))); }
        // CPL unchanged
    } else {
        // Nonconforming: DPL must be <= CPL; CPL becomes DPL
        if dpl > current_cpl { return Err(Exception::new(Vector::GP, Some(gate.selector.0 as u32))); }
        new_cpl = dpl;
    }

    // Target CS cache
    let cs_cache = SegmentCache { base: tdesc.base, limit: tdesc.limit, flags: tdesc.flags, valid: true };

    // If ring change (numerically lower), fetch new stack from TSS (32-bit path)
    let mut new_ss = None;
    if new_cpl < current_cpl {
        let tss_base = cpu.tr.1.base;
        if !cpu.tr.1.valid { return Err(Exception::new(Vector::TS, Some(0))); }
        // offsets for TSS32
        let (esp_off, ss_off) = match new_cpl {
            0 => (0x04u64, 0x08u64),
            1 => (0x0Cu64, 0x10u64),
            2 => (0x14u64, 0x18u64),
            _ => return Err(Exception::new(Vector::TS, Some(0))),
        };
        let mut buf4 = [0u8;4];
        mem.read(tss_base + esp_off, &mut buf4).map_err(|_| Exception::new(Vector::TS, Some(0)))?;
        let esp = u32::from_le_bytes(buf4);
        let mut buf2 = [0u8;2];
        mem.read(tss_base + ss_off, &mut buf2).map_err(|_| Exception::new(Vector::TS, Some(0)))?;
        let ss_sel = SegmentSelector(u16::from_le_bytes(buf2));
        // Load SS cache with checks
        let (ss_sel, ss_cache) = load_data_segment(mem, cpu.gdtr, Some(cpu.ldtr), SegReg::SS, ss_sel, new_cpl)?;
        new_ss = Some((ss_sel, ss_cache, esp));
    }

    let (param_unit, ret_ip_size) = match gate.kind {
        GateKind::Call16 => (2, 2),
        GateKind::Call32 => (4, 4),
        _ => (0, 0),
    };
    Ok(CallResolution { target_sel: gate.selector, target_offset: gate.offset, target_cache: cs_cache, new_cpl, new_ss, param_count: gate.param_count, param_unit, ret_ip_size })
}

pub fn resolve_far_call32_code(cpu: &Cpu, mem: &dyn Memory, current_cpl: u8, sel: SegmentSelector, offset: u32) -> Result<CallResolution, Exception> {
    if sel.index() == 0 { return Err(Exception::new(Vector::GP, Some(0))); }
    let table = if sel.ti() {
        let (_, ldt_cache) = cpu.ldtr;
        if !ldt_cache.valid || !ldt_cache.flags.present() { return Err(Exception::new(Vector::GP, Some(sel.0 as u32))); }
        DescriptorTableReg { base: ldt_cache.base, limit: (ldt_cache.limit & 0xFFFF) as u16 }
    } else { cpu.gdtr };
    let desc = read_descriptor(mem, table, sel)?;
    if !desc.flags.present() { return Err(Exception::new(Vector::NP, Some(sel.0 as u32))); }
    if desc.kind != DescKind::CodeData || !desc.flags.is_code() { return Err(Exception::new(Vector::GP, Some(sel.0 as u32))); }
    let dpl = desc.flags.dpl();
    let rpl = sel.rpl();
    let conforming = desc.flags.contains(DescriptorFlags::DC);
    // For direct far call to code: no privilege change permitted.
    if conforming {
        // Require DPL <= CPL and RPL <= CPL
        if dpl > current_cpl || rpl > current_cpl { return Err(Exception::new(Vector::GP, Some(sel.0 as u32))); }
    } else {
        // Require CPL == DPL and RPL <= CPL
        if dpl != current_cpl || rpl > current_cpl { return Err(Exception::new(Vector::GP, Some(sel.0 as u32))); }
    }
    let cache = SegmentCache { base: desc.base, limit: desc.limit, flags: desc.flags, valid: true };
    Ok(CallResolution { target_sel: sel, target_offset: offset, target_cache: cache, new_cpl: current_cpl, new_ss: None, param_count: 0, param_unit: 0, ret_ip_size: 4 })
}

#[derive(Debug, Clone, Copy)]
pub struct JmpResolution {
    pub target_sel: SegmentSelector,
    pub target_offset: u32,
    pub target_cache: SegmentCache,
    pub new_cpl: u8,
    pub new_ss: Option<(SegmentSelector, SegmentCache, u32)>,
    pub clear_if: bool,
}

pub fn resolve_far_jmp32_code(cpu: &Cpu, mem: &dyn Memory, current_cpl: u8, sel: SegmentSelector, offset: u32) -> Result<JmpResolution, Exception> {
    if sel.index() == 0 { return Err(Exception::new(Vector::GP, Some(0))); }
    let table = if sel.ti() {
        let (_, ldt_cache) = cpu.ldtr;
        if !ldt_cache.valid || !ldt_cache.flags.present() { return Err(Exception::new(Vector::GP, Some(sel.0 as u32))); }
        DescriptorTableReg { base: ldt_cache.base, limit: (ldt_cache.limit & 0xFFFF) as u16 }
    } else { cpu.gdtr };
    let desc = read_descriptor(mem, table, sel)?;
    if !desc.flags.present() { return Err(Exception::new(Vector::NP, Some(sel.0 as u32))); }
    if desc.kind != DescKind::CodeData || !desc.flags.is_code() { return Err(Exception::new(Vector::GP, Some(sel.0 as u32))); }
    let dpl = desc.flags.dpl();
    let rpl = sel.rpl();
    let conforming = desc.flags.contains(DescriptorFlags::DC);
    if conforming {
        if dpl > current_cpl || rpl > current_cpl { return Err(Exception::new(Vector::GP, Some(sel.0 as u32))); }
    } else {
        if dpl != current_cpl || rpl > current_cpl { return Err(Exception::new(Vector::GP, Some(sel.0 as u32))); }
    }
    let cache = SegmentCache { base: desc.base, limit: desc.limit, flags: desc.flags, valid: true };
    Ok(JmpResolution { target_sel: sel, target_offset: offset, target_cache: cache, new_cpl: current_cpl, new_ss: None, clear_if: false })
}

pub fn resolve_jmp_gate32(cpu: &Cpu, mem: &dyn Memory, gate_sel: SegmentSelector, current_cpl: u8) -> Result<JmpResolution, Exception> {
    let table = if gate_sel.ti() {
        let (_, ldt_cache) = cpu.ldtr;
        if !ldt_cache.valid || !ldt_cache.flags.present() { return Err(Exception::new(Vector::GP, Some(gate_sel.0 as u32))); }
        DescriptorTableReg { base: ldt_cache.base, limit: (ldt_cache.limit & 0xFFFF) as u16 }
    } else { cpu.gdtr };
    let gate = read_gate(mem, table, gate_sel)?;
    if !gate.present { return Err(Exception::new(Vector::NP, Some(gate_sel.0 as u32))); }
    // DPL check for far JMP via gate: max(CPL, RPL) <= DPL
    let eff = core::cmp::max(current_cpl, gate_sel.rpl());
    if eff > gate.dpl { return Err(Exception::new(Vector::GP, Some(gate_sel.0 as u32))); }
    // Resolve target code
    let target_table = if gate.selector.ti() {
        let (_, ldt_cache) = cpu.ldtr;
        if !ldt_cache.valid || !ldt_cache.flags.present() { return Err(Exception::new(Vector::GP, Some(gate.selector.0 as u32))); }
        DescriptorTableReg { base: ldt_cache.base, limit: (ldt_cache.limit & 0xFFFF) as u16 }
    } else { cpu.gdtr };
    let tdesc = read_descriptor(mem, target_table, gate.selector)?;
    if !tdesc.flags.present() { return Err(Exception::new(Vector::NP, Some(gate.selector.0 as u32))); }
    if tdesc.kind != DescKind::CodeData || !tdesc.flags.is_code() { return Err(Exception::new(Vector::GP, Some(gate.selector.0 as u32))); }
    let dpl = tdesc.flags.dpl();
    let conforming = tdesc.flags.contains(DescriptorFlags::DC);
    let mut new_cpl = current_cpl;
    if conforming {
        if dpl > current_cpl { return Err(Exception::new(Vector::GP, Some(gate.selector.0 as u32))); }
    } else {
        if dpl > current_cpl { return Err(Exception::new(Vector::GP, Some(gate.selector.0 as u32))); }
        new_cpl = dpl;
    }
    let target_cache = SegmentCache { base: tdesc.base, limit: tdesc.limit, flags: tdesc.flags, valid: true };
    let mut new_ss = None;
    if new_cpl < current_cpl {
        let tss_base = cpu.tr.1.base;
        if !cpu.tr.1.valid { return Err(Exception::new(Vector::TS, Some(0))); }
        let (esp_off, ss_off) = match new_cpl { 0 => (0x04u64, 0x08u64), 1 => (0x0Cu64, 0x10u64), 2 => (0x14u64, 0x18u64), _ => return Err(Exception::new(Vector::TS, Some(0))) };
        let mut buf4 = [0u8;4]; mem.read(tss_base + esp_off, &mut buf4).map_err(|_| Exception::new(Vector::TS, Some(0)))?; let esp = u32::from_le_bytes(buf4);
        let mut buf2 = [0u8;2]; mem.read(tss_base + ss_off, &mut buf2).map_err(|_| Exception::new(Vector::TS, Some(0)))?; let ss_sel = SegmentSelector(u16::from_le_bytes(buf2));
        let (ss_sel, ss_cache) = load_data_segment(mem, cpu.gdtr, Some(cpu.ldtr), SegReg::SS, ss_sel, new_cpl)?;
        new_ss = Some((ss_sel, ss_cache, esp));
    }
    Ok(JmpResolution { target_sel: gate.selector, target_offset: gate.offset, target_cache, new_cpl, new_ss, clear_if: false })
}

#[derive(Debug, Clone, Copy)]
pub struct TaskSwitch { pub tss_sel: SegmentSelector }

pub fn resolve_call_task_gate32(cpu: &Cpu, mem: &dyn Memory, gate_sel: SegmentSelector, current_cpl: u8) -> Result<TaskSwitch, Exception> {
    let table = if gate_sel.ti() {
        let (_, ldt_cache) = cpu.ldtr;
        if !ldt_cache.valid || !ldt_cache.flags.present() { return Err(Exception::new(Vector::GP, Some(gate_sel.0 as u32))); }
        DescriptorTableReg { base: ldt_cache.base, limit: (ldt_cache.limit & 0xFFFF) as u16 }
    } else { cpu.gdtr };
    let gate = read_gate(mem, table, gate_sel)?;
    if !matches!(gate.kind, GateKind::TaskGate) { return Err(Exception::new(Vector::GP, Some(gate_sel.0 as u32))); }
    if !gate.present { return Err(Exception::new(Vector::NP, Some(gate_sel.0 as u32))); }
    let eff = core::cmp::max(current_cpl, gate_sel.rpl());
    if eff > gate.dpl { return Err(Exception::new(Vector::GP, Some(gate_sel.0 as u32))); }
    Ok(TaskSwitch { tss_sel: gate.selector })
}

pub fn resolve_jmp_task_gate32(cpu: &Cpu, mem: &dyn Memory, gate_sel: SegmentSelector, current_cpl: u8) -> Result<TaskSwitch, Exception> {
    resolve_call_task_gate32(cpu, mem, gate_sel, current_cpl)
}

pub fn arpl(dst: SegmentSelector, src: SegmentSelector) -> (SegmentSelector, bool) {
    // Adjust RPL of dst to max(dst.rpl, src.rpl); ZF=1 if changed
    let dr = dst.rpl();
    let sr = src.rpl();
    if dr < sr {
        (SegmentSelector((dst.0 & !0x3) | sr as u16), true)
    } else {
        (dst, false)
    }
}

// Instruction-level helpers for moving/loading segment registers
pub fn instr_mov_sreg(cpu: &mut Cpu, mem: &dyn Memory, seg: SegReg, sel: SegmentSelector, cpl: u8) -> Result<(), Exception> {
    let (s, c) = load_data_segment(mem, cpu.gdtr, Some(cpu.ldtr), seg, sel, cpl)?;
    cpu.segs.set(seg, s, c);
    Ok(())
}

fn read_ptr16_32(mem: &dyn Memory, addr: u64) -> Result<(u32, SegmentSelector), Exception> {
    let mut off = [0u8;4];
    let mut sel = [0u8;2];
    mem.read(addr, &mut off).map_err(|_| Exception::new(Vector::SS, Some(0)))?;
    mem.read(addr + 4, &mut sel).map_err(|_| Exception::new(Vector::SS, Some(0)))?;
    Ok((u32::from_le_bytes(off), SegmentSelector(u16::from_le_bytes(sel))))
}

pub fn instr_lss32(cpu: &mut Cpu, mem: &dyn Memory, addr: u64, cpl: u8) -> Result<u32, Exception> {
    let (offset, sel) = read_ptr16_32(mem, addr)?;
    let (s, c) = load_data_segment(mem, cpu.gdtr, Some(cpu.ldtr), SegReg::SS, sel, cpl)?;
    cpu.segs.set(SegReg::SS, s, c);
    Ok(offset)
}

#[derive(Debug, Clone, Copy)]
pub enum InterruptResolution {
    ToCode {
        target_sel: SegmentSelector,
        target_offset: u32,
        target_cache: SegmentCache,
        new_cpl: u8,
        new_ss: Option<(SegmentSelector, SegmentCache, u32)>,
        is_trap: bool,
        clear_if: bool,
    },
    TaskSwitch { tss_sel: SegmentSelector },
}

pub fn resolve_interrupt_gate(cpu: &Cpu, mem: &dyn Memory, vector: u8, current_cpl: u8, software: bool) -> Result<InterruptResolution, Exception> {
    // Read gate from IDT
    let idtr = cpu.idtr;
    let sel = SegmentSelector((vector as u16) << 3);
    let gate = read_gate(mem, idtr, sel)?;
    if !gate.present { return Err(Exception::new(Vector::NP, Some((vector as u32) << 3))); }
    // DPL check applies to software INT only
    if software {
        let eff = current_cpl; // RPL for INT3/INTO/INT imm8 is 0; CPL is used
        if eff > gate.dpl { return Err(Exception::new(Vector::GP, Some((vector as u32) << 3))); }
    }
    match gate.kind {
        GateKind::TaskGate => {
            return Ok(InterruptResolution::TaskSwitch { tss_sel: gate.selector });
        }
        GateKind::Interrupt16 | GateKind::Interrupt32 | GateKind::Trap16 | GateKind::Trap32 => {
            // Resolve target code segment
            let target_table = if gate.selector.ti() {
                let (_, ldt_cache) = cpu.ldtr;
                if !ldt_cache.valid || !ldt_cache.flags.present() { return Err(Exception::new(Vector::GP, Some(gate.selector.0 as u32))); }
                DescriptorTableReg { base: ldt_cache.base, limit: (ldt_cache.limit & 0xFFFF) as u16 }
            } else { cpu.gdtr };
            let tdesc = read_descriptor(mem, target_table, gate.selector)?;
            if !tdesc.flags.present() { return Err(Exception::new(Vector::NP, Some(gate.selector.0 as u32))); }
            if tdesc.kind != DescKind::CodeData || !tdesc.flags.is_code() { return Err(Exception::new(Vector::GP, Some(gate.selector.0 as u32))); }
            let dpl = tdesc.flags.dpl();
            let conforming = tdesc.flags.contains(DescriptorFlags::DC);
            let mut new_cpl = current_cpl;
            if conforming {
                if dpl > current_cpl { return Err(Exception::new(Vector::GP, Some(gate.selector.0 as u32))); }
            } else {
                if dpl > current_cpl { return Err(Exception::new(Vector::GP, Some(gate.selector.0 as u32))); }
                new_cpl = dpl;
            }
            let cs_cache = SegmentCache { base: tdesc.base, limit: tdesc.limit, flags: tdesc.flags, valid: true };
            let mut new_ss = None;
            if new_cpl < current_cpl {
                // Use TSS to get new SS:ESP
                let tss_base = cpu.tr.1.base;
                if !cpu.tr.1.valid { return Err(Exception::new(Vector::TS, Some(0))); }
                let (esp_off, ss_off) = match new_cpl {
                    0 => (0x04u64, 0x08u64),
                    1 => (0x0Cu64, 0x10u64),
                    2 => (0x14u64, 0x18u64),
                    _ => return Err(Exception::new(Vector::TS, Some(0))),
                };
                let mut buf4 = [0u8;4];
                mem.read(tss_base + esp_off, &mut buf4).map_err(|_| Exception::new(Vector::TS, Some(0)))?;
                let esp = u32::from_le_bytes(buf4);
                let mut buf2 = [0u8;2];
                mem.read(tss_base + ss_off, &mut buf2).map_err(|_| Exception::new(Vector::TS, Some(0)))?;
                let ss_sel = SegmentSelector(u16::from_le_bytes(buf2));
        let (ss_sel, ss_cache) = load_data_segment(mem, cpu.gdtr, Some(cpu.ldtr), SegReg::SS, ss_sel, new_cpl)?;
                new_ss = Some((ss_sel, ss_cache, esp));
            }
            let is_trap = matches!(gate.kind, GateKind::Trap16 | GateKind::Trap32);
            let clear_if = matches!(gate.kind, GateKind::Interrupt16 | GateKind::Interrupt32);
            return Ok(InterruptResolution::ToCode { target_sel: gate.selector, target_offset: gate.offset, target_cache: cs_cache, new_cpl, new_ss, is_trap, clear_if });
        }
        _ => return Err(Exception::new(Vector::GP, Some((vector as u32) << 3))),
    }
}

#[derive(Debug, Clone, Copy)]
pub struct IretResolution {
    pub target_sel: SegmentSelector,
    pub target_offset: u32,
    pub target_cache: SegmentCache,
    pub rflags: u32,
    pub new_cpl: u8,
    pub new_ss: Option<(SegmentSelector, SegmentCache, u32)>,
}

pub fn resolve_iret32(cpu: &Cpu, mem: &dyn Memory, current_cpl: u8, _cur_ss: (SegmentSelector, SegmentCache), esp: u32) -> Result<(IretResolution, u32), Exception> {
    // Pop EIP (4), CS (2), EFLAGS (4) in 32-bit operand size
    let mut buf4 = [0u8;4];
    mem.read(esp as u64, &mut buf4).map_err(|_| Exception::new(Vector::SS, Some(0)))?;
    let eip = u32::from_le_bytes(buf4);
    let mut buf2 = [0u8;2];
    mem.read(esp as u64 + 4, &mut buf2).map_err(|_| Exception::new(Vector::SS, Some(0)))?;
    let cs_sel = SegmentSelector(u16::from_le_bytes(buf2));
    mem.read(esp as u64 + 6, &mut buf4).map_err(|_| Exception::new(Vector::SS, Some(0)))?;
    let rflags = u32::from_le_bytes(buf4);

    // Resolve target CS
    if cs_sel.index() == 0 { return Err(Exception::new(Vector::GP, Some(0))); }
    let table = if cs_sel.ti() {
        let (_, ldt_cache) = cpu.ldtr;
        if !ldt_cache.valid || !ldt_cache.flags.present() { return Err(Exception::new(Vector::GP, Some(cs_sel.0 as u32))); }
        DescriptorTableReg { base: ldt_cache.base, limit: (ldt_cache.limit & 0xFFFF) as u16 }
    } else { cpu.gdtr };
    let tdesc = read_descriptor(mem, table, cs_sel)?;
    if !tdesc.flags.present() { return Err(Exception::new(Vector::NP, Some(cs_sel.0 as u32))); }
    if tdesc.kind != DescKind::CodeData || !tdesc.flags.is_code() { return Err(Exception::new(Vector::GP, Some(cs_sel.0 as u32))); }

    let dpl = tdesc.flags.dpl();
    let rpl = cs_sel.rpl();
    let conforming = tdesc.flags.contains(DescriptorFlags::DC);
    let mut new_cpl = current_cpl;
    let mut new_ss = None;
    // Default stack advance for same-privilege IRETD is 10 bytes (EIP:4 + CS:2 + EFLAGS:4)
    let mut new_sp = esp.wrapping_add(10);

    if conforming {
        // IRET to conforming: no privilege change; require DPL <= CPL and RPL <= CPL
        if dpl > current_cpl || rpl > current_cpl { return Err(Exception::new(Vector::GP, Some(cs_sel.0 as u32))); }
    } else {
        // Non-conforming: new CPL = RPL
        if rpl < current_cpl { return Err(Exception::new(Vector::GP, Some(cs_sel.0 as u32))); }
        if dpl != rpl { return Err(Exception::new(Vector::GP, Some(cs_sel.0 as u32))); }
        if rpl > current_cpl {
            // Return to outer privilege: pop SS:ESP and validate SS
            mem.read(esp as u64 + 10, &mut buf4).map_err(|_| Exception::new(Vector::SS, Some(0)))?;
            let new_esp = u32::from_le_bytes(buf4);
            let mut buf2 = [0u8;2];
            mem.read(esp as u64 + 14, &mut buf2).map_err(|_| Exception::new(Vector::SS, Some(0)))?;
            let ss_sel = SegmentSelector(u16::from_le_bytes(buf2));
            // Load SS descriptor (must be writable data), then check DPL==new CPL and RPL==new CPL
            let (ss_sel, ss_cache) = load_data_segment(mem, cpu.gdtr, Some(cpu.ldtr), SegReg::SS, ss_sel, new_cpl)?;
            if ss_cache.flags.dpl() != rpl || ss_sel.rpl() != rpl { return Err(Exception::new(Vector::GP, Some(ss_sel.0 as u32))); }
            new_ss = Some((ss_sel, ss_cache, new_esp));
            new_cpl = rpl;
            // Total bytes consumed on current stack when returning to outer privilege: 16
            // (EIP:4 + CS:2 + EFLAGS:4 + ESP:4 + SS:2)
            new_sp = esp.wrapping_add(16);
        }
    }

    let cs_cache = SegmentCache { base: tdesc.base, limit: tdesc.limit, flags: tdesc.flags, valid: true };
    Ok((IretResolution { target_sel: cs_sel, target_offset: eip, target_cache: cs_cache, rflags, new_cpl, new_ss }, new_sp))
}

#[derive(Debug, Clone, Copy)]
pub struct RetfResolution {
    pub target_sel: SegmentSelector,
    pub target_offset: u32,
    pub target_cache: SegmentCache,
    pub new_cpl: u8,
    pub new_ss: Option<(SegmentSelector, SegmentCache, u32)>,
}

pub fn resolve_retf32(cpu: &Cpu, mem: &dyn Memory, current_cpl: u8, _cur_ss: (SegmentSelector, SegmentCache), esp: u32, imm16: u16) -> Result<(RetfResolution, u32), Exception> {
    // Pop EIP (4), CS (2)
    let mut buf4 = [0u8;4];
    mem.read(esp as u64, &mut buf4).map_err(|_| Exception::new(Vector::SS, Some(0)))?;
    let eip = u32::from_le_bytes(buf4);
    let mut buf2 = [0u8;2];
    mem.read(esp as u64 + 4, &mut buf2).map_err(|_| Exception::new(Vector::SS, Some(0)))?;
    let cs_sel = SegmentSelector(u16::from_le_bytes(buf2));

    if cs_sel.index() == 0 { return Err(Exception::new(Vector::GP, Some(0))); }
    let table = if cs_sel.ti() {
        let (_, ldt_cache) = cpu.ldtr;
        if !ldt_cache.valid || !ldt_cache.flags.present() { return Err(Exception::new(Vector::GP, Some(cs_sel.0 as u32))); }
        DescriptorTableReg { base: ldt_cache.base, limit: (ldt_cache.limit & 0xFFFF) as u16 }
    } else { cpu.gdtr };
    let tdesc = read_descriptor(mem, table, cs_sel)?;
    if !tdesc.flags.present() { return Err(Exception::new(Vector::NP, Some(cs_sel.0 as u32))); }
    if tdesc.kind != DescKind::CodeData || !tdesc.flags.is_code() { return Err(Exception::new(Vector::GP, Some(cs_sel.0 as u32))); }

    let dpl = tdesc.flags.dpl();
    let rpl = cs_sel.rpl();
    let conforming = tdesc.flags.contains(DescriptorFlags::DC);
    let mut new_cpl = current_cpl;
    let mut new_ss = None;
    // Default same-privilege far RET consumes 6 bytes (EIP:4 + CS:2)
    let mut new_sp = esp.wrapping_add(6);

    if conforming {
        // Far return to conforming segment: no privilege change; require DPL <= CPL and RPL <= CPL
        if dpl > current_cpl || rpl > current_cpl { return Err(Exception::new(Vector::GP, Some(cs_sel.0 as u32))); }
    } else {
        if rpl < current_cpl { return Err(Exception::new(Vector::GP, Some(cs_sel.0 as u32))); }
        if rpl == current_cpl {
            // Same-privilege return: require DPL == CPL
            if dpl != current_cpl { return Err(Exception::new(Vector::GP, Some(cs_sel.0 as u32))); }
        } else {
            // Return to outer privilege (numerically higher): DPL must equal RPL; new CPL=RPL
            if dpl != rpl { return Err(Exception::new(Vector::GP, Some(cs_sel.0 as u32))); }
            // Pop new ESP and SS from current stack
            mem.read(esp as u64 + 6, &mut buf4).map_err(|_| Exception::new(Vector::SS, Some(0)))?;
            let new_esp = u32::from_le_bytes(buf4);
            let mut buf2 = [0u8;2];
            mem.read(esp as u64 + 10, &mut buf2).map_err(|_| Exception::new(Vector::SS, Some(0)))?;
            let ss_sel = SegmentSelector(u16::from_le_bytes(buf2));
            // Validate SS: writable data, DPL == new CPL, RPL == new CPL
            let (ss_sel, ss_cache) = load_data_segment(mem, cpu.gdtr, Some(cpu.ldtr), SegReg::SS, ss_sel, new_cpl)?;
            if ss_cache.flags.dpl() != rpl || ss_sel.rpl() != rpl { return Err(Exception::new(Vector::GP, Some(ss_sel.0 as u32))); }
            new_ss = Some((ss_sel, ss_cache, new_esp));
            new_cpl = rpl;
            // Total bytes consumed on current stack when returning to outer privilege: 12
            // (EIP:4 + CS:2 + ESP:4 + SS:2)
            new_sp = esp.wrapping_add(12);
        }
    }

    // Apply imm16 stack adjustment on destination stack (same ring: current, or new ring's stack after load)
    let adj = imm16 as u32;
    if let Some((ss_sel, ss_cache, esp_new)) = new_ss {
        new_ss = Some((ss_sel, ss_cache, esp_new.wrapping_add(adj)));
    } else {
        new_sp = new_sp.wrapping_add(adj);
    }

    let cs_cache = SegmentCache { base: tdesc.base, limit: tdesc.limit, flags: tdesc.flags, valid: true };
    Ok((RetfResolution { target_sel: cs_sel, target_offset: eip, target_cache: cs_cache, new_cpl, new_ss }, new_sp))
}

#[cfg(test)]

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{FlatMem, Memory};
    use crate::Cpu;

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
    fn parse_descriptor_granularity_and_dpl() {
        // Code segment, readable, DPL=3, present, gran=4K, limit=0xFFFFF -> expands to 0xFFFFF_FFFF
        let raw = mk_seg_desc(0x1234_0000, 0xFFFFF, true, 0b1010, true, 3, true, false, true, false);
        let pd = super::parse_descriptor(raw);
        assert!(pd.flags.contains(DescriptorFlags::G));
        assert_eq!(pd.flags.dpl(), 3);
        assert_eq!(pd.limit, 0xFFFFF_FFFF);
        assert_eq!(pd.base as u32 & 0xFFFF_0000, 0x1234_0000);
    }

    #[test]
    fn load_ds_data_ok_and_null_sel_behavior() {
        let mut mem = FlatMem::new(0x20000);
        let gdtr = DescriptorTableReg { base: 0x1000, limit: 0x00FF };
        // Data segment: RW, DPL=3, present
        let data = mk_seg_desc(0x2000, 0x0FFF, false, 0b0010, true, 3, true, false, true, false);
        write_desc(&mut mem, gdtr.base, 3, data);
        // DS load succeeds at CPL=3 with RPL=3
        let (sel, cache) = load_data_segment(&mem, gdtr, None, SegReg::DS, SegmentSelector((3<<3)|3), 3).unwrap();
        assert_eq!(sel.index(), 3);
        assert!(cache.valid);
        assert_eq!(cache.base, 0x2000);
        // Null selector clears data segs, but SS null faults
        let (nsel, ncache) = load_data_segment(&mem, gdtr, None, SegReg::DS, SegmentSelector(0), 3).unwrap();
        assert_eq!(nsel.0, 0);
        assert_eq!(ncache.valid, false);
        assert!(load_data_segment(&mem, gdtr, None, SegReg::SS, SegmentSelector(0), 3).is_err());
    }

    #[test]
    fn lar_lsl_verr_verw() {
        let mut mem = FlatMem::new(0x20000);
        let gdtr = DescriptorTableReg { base: 0x1000, limit: 0x00FF };
        // Readable code (type=1010), DPL=3, present
        let code_r = mk_seg_desc(0x3000, 0x7FFF, false, 0b1010, true, 3, true, false, true, false);
        // Writable data (type=0010), DPL=3, present
        let data_w = mk_seg_desc(0x4000, 0x00FF, false, 0b0010, true, 3, true, false, true, false);
        write_desc(&mut mem, gdtr.base, 2, code_r);
        write_desc(&mut mem, gdtr.base, 5, data_w);

        // LAR returns AR for code/data, None otherwise
        let ar = lar(&mem, gdtr, None, SegmentSelector((2<<3)|3)).unwrap().unwrap();
        assert!( (ar & (1<<3)) != 0 ); // EXEC set
        assert!( (ar & (1<<1)) != 0 ); // readable/writable bit set
        let lim = lsl(&mem, gdtr, None, SegmentSelector((5<<3)|3)).unwrap().unwrap();
        assert_eq!(lim, 0x00FF);

        // VERR: readable code allowed when DPL >= max(CPL,RPL) for non-conforming
        assert!(verr(&mem, gdtr, None, 3, SegmentSelector((2<<3)|3)));
        // VERW: writable data allowed
        assert!(verw(&mem, gdtr, None, 3, SegmentSelector((5<<3)|3)));
    }

    #[test]
    fn instr_ltr_sets_busy_bit() {
        let mut mem = FlatMem::new(0x20000);
        let gdtr = DescriptorTableReg { base: 0x1000, limit: 0x00FF };
        // 32-bit available TSS at index 6 (type=1001, s=0)
        let tss_base = 0x5000u32;
        let tss_desc = mk_seg_desc(tss_base, 0x0067, false, 0b1001, false, 0, true, false, true, false);
        write_desc(&mut mem, gdtr.base, 6, tss_desc);
        let mut cpu = Cpu::new();
        cpu.gdtr = gdtr;
        // LTR should set busy bit in descriptor
        instr_ltr(&mut cpu, &mut mem, SegmentSelector(6<<3)).unwrap();
        // Read back descriptor and confirm busy (type low nibble OR 0b0010 -> 0b1011)
        let raw = super::read_descriptor_raw(&mem, gdtr, SegmentSelector(6<<3)).unwrap();
        assert_eq!(raw[5] & 0x0F, 0b1011);
        // CPU.TR cache set
        assert_eq!(cpu.tr.0.index(), 6);
        assert!(cpu.tr.1.valid);
    }

    #[test]
    fn arpl_adjusts_rpl() {
        let (new, zf) = arpl(SegmentSelector((5<<3)|1), SegmentSelector((7<<3)|3));
        assert_eq!(new.rpl(), 3);
        assert!(zf);
        let (new2, zf2) = arpl(SegmentSelector((5<<3)|3), SegmentSelector((7<<3)|1));
        assert_eq!(new2.rpl(), 3);
        assert!(!zf2);
    }

    #[test]
    fn ss_load_requires_writable_and_priv_checks() {
        let mut mem = FlatMem::new(0x20000);
        let gdtr = DescriptorTableReg { base: 0x1000, limit: 0x00FF };
        // Writable data DPL=3 present at idx 5
        let data3 = mk_seg_desc(0x7000, 0x0FFF, false, 0b0010, true, 3, true, false, true, false);
        write_desc(&mut mem, gdtr.base, 5, data3);
        // Writable data DPL=2 present at idx 6
        let data2 = mk_seg_desc(0x7100, 0x0FFF, false, 0b0010, true, 2, true, false, true, false);
        write_desc(&mut mem, gdtr.base, 6, data2);
        // Not-present at idx 7
        let data_np = mk_seg_desc(0x7200, 0x0FFF, false, 0b0010, true, 3, false, false, true, false);
        write_desc(&mut mem, gdtr.base, 7, data_np);

        // OK: SS load with RPL=3, DPL=3 at CPL=3
        let (_s, cache_ok) = load_data_segment(&mem, gdtr, None, SegReg::SS, SegmentSelector((5<<3)|3), 3).unwrap();
        assert!(cache_ok.valid);
        // GP: RPL mismatch (RPL=2, CPL=3)
        let err = load_data_segment(&mem, gdtr, None, SegReg::SS, SegmentSelector((5<<3)|2), 3).unwrap_err();
        assert_eq!(err.vector, Vector::GP);
        // GP: DPL mismatch (DPL=2, CPL=3)
        let err2 = load_data_segment(&mem, gdtr, None, SegReg::SS, SegmentSelector((6<<3)|3), 3).unwrap_err();
        assert_eq!(err2.vector, Vector::GP);
        // SS: not present
        let err3 = load_data_segment(&mem, gdtr, None, SegReg::SS, SegmentSelector((7<<3)|3), 3).unwrap_err();
        assert_eq!(err3.vector, Vector::SS);
    }

    #[test]
    fn ds_load_nonconforming_code_ok_conforming_rejected() {
        let mut mem = FlatMem::new(0x20000);
        let gdtr = DescriptorTableReg { base: 0x1000, limit: 0x00FF };
        // Non-conforming readable code (type=1010, DC=0)
        let code_nc = mk_seg_desc(0x3000, 0x0FFF, false, 0b1010, true, 3, true, false, true, false);
        // Conforming readable code (type=1010 with C=1 -> typ bit2 set; in our builder DC bit is bit2, so set typ=1110)
        let code_c = mk_seg_desc(0x3100, 0x0FFF, false, 0b1110, true, 3, true, false, true, false);
        write_desc(&mut mem, gdtr.base, 2, code_nc);
        write_desc(&mut mem, gdtr.base, 4, code_c);
        // At CPL=3, RPL=3
        let (_s1, c1) = load_data_segment(&mem, gdtr, None, SegReg::DS, SegmentSelector((2<<3)|3), 3).unwrap();
        assert!(c1.valid);
        // Conforming code should be rejected for DS load
        let e = load_data_segment(&mem, gdtr, None, SegReg::DS, SegmentSelector((4<<3)|3), 3).unwrap_err();
        assert_eq!(e.vector, Vector::GP);
    }
}
