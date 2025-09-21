pub type u1 = bool;
pub type u8x10 = [u8; 10]; // 80-bit storage helper for x87

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Width {
    W8,
    W16,
    W32,
    W64,
}

impl Width {
    pub fn mask(self) -> u64 {
        match self {
            Width::W8 => 0xFF,
            Width::W16 => 0xFFFF,
            Width::W32 => 0xFFFF_FFFF,
            Width::W64 => 0xFFFF_FFFF_FFFF_FFFF,
        }
    }
}

