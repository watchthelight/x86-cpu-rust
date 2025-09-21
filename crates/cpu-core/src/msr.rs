use std::collections::HashMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Msr(pub u32);

// Minimal architectural MSRs for scaffolding; full map to be added.
pub const IA32_APIC_BASE: Msr = Msr(0x1B);
pub const IA32_EFER: Msr = Msr(0xC000_0080);
pub const IA32_PAT: Msr = Msr(0x277);
pub const IA32_TSC: Msr = Msr(0x10);
pub const IA32_FS_BASE: Msr = Msr(0xC000_0100);
pub const IA32_GS_BASE: Msr = Msr(0xC000_0101);
pub const IA32_KERNEL_GS_BASE: Msr = Msr(0xC000_0102);
pub const IA32_STAR: Msr = Msr(0xC000_0081);
pub const IA32_LSTAR: Msr = Msr(0xC000_0082);
pub const IA32_FMASK: Msr = Msr(0xC000_0084);

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct MsrMap {
    map: HashMap<u32, u64>,
}

impl MsrMap {
    pub fn read(&self, msr: Msr) -> Option<u64> { self.map.get(&msr.0).copied() }
    pub fn write(&mut self, msr: Msr, val: u64) { self.map.insert(msr.0, val); }
}

