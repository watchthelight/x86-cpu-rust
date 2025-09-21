use bitflags::bitflags;
use crate::types::Width;

bitflags! {
    #[derive(Default, Debug, serde::Serialize, serde::Deserialize)]
    pub struct RFlags: u64 {
        const CF = 1 << 0;   // Carry
        const PF = 1 << 2;   // Parity
        const AF = 1 << 4;   // Aux carry
        const ZF = 1 << 6;   // Zero
        const SF = 1 << 7;   // Sign
        const TF = 1 << 8;   // Trap
        const IF = 1 << 9;   // Interrupt enable
        const DF = 1 << 10;  // Direction
        const OF = 1 << 11;  // Overflow
        const IOPL0 = 1 << 12; // IOPL bit 0
        const IOPL1 = 1 << 13; // IOPL bit 1
        const NT = 1 << 14;  // Nested task
        const RF = 1 << 16;  // Resume
        const VM = 1 << 17;  // Virtual 8086
        const AC = 1 << 18;  // Alignment check
        const VIF = 1 << 19; // Virtual IF
        const VIP = 1 << 20; // Virtual IF pending
        const ID = 1 << 21;  // CPUID available
    }
}

impl RFlags {
    pub fn iopl(self) -> u8 {
        ((self.bits() >> 12) & 0b11) as u8
    }
    pub fn with_iopl(mut self, iopl: u8) -> Self {
        let cleared = self.bits() & !(0b11 << 12);
        let val = (iopl as u64 & 0b11) << 12;
        RFlags::from_bits_retain(cleared | val)
    }
}

#[inline]
fn parity8(x: u8) -> bool {
    (x.count_ones() & 1) == 0
}

#[derive(Debug, Clone, Copy)]
pub struct FlagsOut {
    pub cf: bool,
    pub pf: bool,
    pub af: bool,
    pub zf: bool,
    pub sf: bool,
    pub of: bool,
}

#[inline]
pub fn alu_add_flags(width: Width, a: u64, b: u64, carry_in: bool) -> FlagsOut {
    let mask = width.mask();
    let aw = a & mask;
    let bw = b & mask;
    let cin = if carry_in { 1 } else { 0 };
    let full = aw as u128 + bw as u128 + cin as u128;
    let res = (full as u64) & mask;
    let msb = match width {
        Width::W8 => 7,
        Width::W16 => 15,
        Width::W32 => 31,
        Width::W64 => 63,
    };
    let sign_a = ((aw >> msb) & 1) != 0;
    let sign_b = ((bw >> msb) & 1) != 0;
    let sign_r = ((res >> msb) & 1) != 0;

    let cf = (full >> (msb + 1)) != 0;
    let zf = res == 0;
    let sf = sign_r;
    let pf = parity8(res as u8);
    let af = (((aw ^ bw ^ res) >> 4) & 1) != 0; // BCD carry
    let of = (sign_a == sign_b) && (sign_r != sign_a);

    FlagsOut { cf, pf, af, zf, sf, of }
}

#[inline]
pub fn alu_sub_flags(width: Width, a: u64, b: u64, borrow_in: bool) -> (FlagsOut, u64) {
    let mask = width.mask();
    let aw = a & mask;
    let bw = b & mask;
    let bin = if borrow_in { 1 } else { 0 };
    let full = (aw as u128).wrapping_sub(bw as u128).wrapping_sub(bin as u128);
    let res = (full as u64) & mask;
    let msb = match width { Width::W8 => 7, Width::W16 => 15, Width::W32 => 31, Width::W64 => 63 };

    let sign_a = ((aw >> msb) & 1) != 0;
    let sign_b = ((bw >> msb) & 1) != 0;
    let sign_r = ((res >> msb) & 1) != 0;

    // For subtraction, CF is set if a < b + bin (unsigned borrow occurred)
    let cf = (aw as u128) < ((bw as u128) + (bin as u128));
    let zf = res == 0;
    let sf = sign_r;
    let pf = parity8(res as u8);
    let af = (((aw ^ bw ^ res) >> 4) & 1) != 0;
    let of = (sign_a != sign_b) && (sign_r != sign_a);

    (FlagsOut { cf, pf, af, zf, sf, of }, res)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add8_flags_basic() {
        let f = alu_add_flags(Width::W8, 0x7F, 0x01, false);
        assert_eq!(f.cf, false);
        assert_eq!(f.of, true); // 127 + 1 -> -128 overflow
        assert_eq!(f.sf, true);
        assert_eq!(f.zf, false);
    }

    #[test]
    fn add8_carry() {
        let f = alu_add_flags(Width::W8, 0xFF, 0x01, false);
        assert_eq!(f.cf, true);
        assert_eq!(f.zf, true);
        assert_eq!(f.of, false);
    }

    #[test]
    fn sub16_borrow() {
        let (f, r) = alu_sub_flags(Width::W16, 0x0000, 0x0001, false);
        assert_eq!(f.cf, true);
        assert_eq!(r, 0xFFFF);
        assert_eq!(f.sf, true);
        assert_eq!(f.zf, false);
    }
}
