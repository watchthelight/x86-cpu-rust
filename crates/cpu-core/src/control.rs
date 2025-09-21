use bitflags::bitflags;
use serde::{Deserialize, Serialize};

bitflags! {
    #[derive(Debug, Default, Serialize, Deserialize)]
    pub struct Cr0: u64 {
        const PE = 1<<0;   // Protection Enable
        const MP = 1<<1;   // Monitor Coprocessor
        const EM = 1<<2;   // Emulation
        const TS = 1<<3;   // Task Switched
        const ET = 1<<4;   // Extension Type (obsolete)
        const NE = 1<<5;   // Numeric Error
        const WP = 1<<16;  // Write Protect
        const AM = 1<<18;  // Alignment Mask
        const NW = 1<<29;  // Not Write-through
        const CD = 1<<30;  // Cache Disable
        const PG = 1<<31;  // Paging
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct Cr3 {
    pub pcid: Option<u16>,
    pub pml4: u64,
}

bitflags! {
    #[derive(Debug, Default, Serialize, Deserialize)]
    pub struct Cr4: u64 {
        const VME = 1<<0;
        const PVI = 1<<1;
        const TSD = 1<<2;
        const DE  = 1<<3;
        const PSE = 1<<4;
        const PAE = 1<<5;
        const MCE = 1<<6;
        const PGE = 1<<7;
        const PCE = 1<<8;
        const OSFXSR = 1<<9;
        const OSXMMEXCPT = 1<<10;
        const UMIP = 1<<11;
        const LA57 = 1<<12;
        const VMXE = 1<<13;
        const SMXE = 1<<14;
        const FSGSBASE = 1<<16;
        const PCIDE = 1<<17;
        const OSXSAVE = 1<<18;
        const SMEP = 1<<20;
        const SMAP = 1<<21;
        const PKE = 1<<22;
    }
}

bitflags! {
    #[derive(Debug, Default, Serialize, Deserialize)]
    pub struct Efer: u64 {
        const SCE = 1<<0;   // SYSCALL Enable
        const LME = 1<<8;   // Long Mode Enable
        const LMA = 1<<10;  // Long Mode Active (read-only architectural)
        const NXE = 1<<11;  // No-Execute Enable
        const SVME = 1<<12; // SVM enable
        const LMSLE = 1<<13;
        const FFXSR = 1<<14;
    }
}
