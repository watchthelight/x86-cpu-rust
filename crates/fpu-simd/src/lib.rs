use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct X87Reg(pub [u8; 10]); // 80-bit

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X87State {
    pub st: [X87Reg; 8],
    pub cw: u16,
    pub sw: u16,
    pub tw: u16,
    pub fip: u64,
    pub fdp: u64,
}

impl Default for X87State {
    fn default() -> Self {
        Self { st: [X87Reg([0;10]); 8], cw: 0x037F, sw: 0, tw: 0xFFFF, fip: 0, fdp: 0 }
    }
}

bitflags::bitflags! {
    #[derive(Copy, Clone, Debug, Default, Serialize, Deserialize)]
    pub struct Mxcsr: u32 {
        const IE = 1<<0; const DE = 1<<1; const ZE = 1<<2; const OE = 1<<3; const UE = 1<<4; const PE = 1<<5;
        const DAZ = 1<<6; const IM = 1<<7; const DM = 1<<8; const ZM = 1<<9; const OM = 1<<10; const UM = 1<<11; const PM = 1<<12;
        const RC_RN = 0; const RC_RZ = 0b01<<13; const RC_RM = 0b10<<13; const RC_RP = 0b11<<13;
        const FZ = 1<<15;
    }
}

#[derive(Debug, Clone)]
pub struct SimdState {
    pub xmm: [[u8; 16]; 16],
    pub ymm: [[u8; 32]; 16],
    pub zmm: [[u8; 64]; 32],
    pub k: [u64; 8],
    pub mxcsr: Mxcsr,
}

impl Default for SimdState {
    fn default() -> Self {
        Self { xmm: [[0u8;16];16], ymm: [[0u8;32];16], zmm: [[0u8;64];32], k: [0u64;8], mxcsr: Mxcsr::default() }
    }
}
