use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum Gpr {
    RAX = 0,
    RCX = 1,
    RDX = 2,
    RBX = 3,
    RSP = 4,
    RBP = 5,
    RSI = 6,
    RDI = 7,
    R8 = 8,
    R9 = 9,
    R10 = 10,
    R11 = 11,
    R12 = 12,
    R13 = 13,
    R14 = 14,
    R15 = 15,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegFile {
    regs: [u64; 16],
    pub rip: u64,
}

impl Default for RegFile {
    fn default() -> Self {
        Self { regs: [0; 16], rip: 0 }
    }
}

impl RegFile {
    #[inline]
    pub fn get(&self, r: Gpr) -> u64 { self.regs[r as usize] }

    #[inline]
    pub fn set(&mut self, r: Gpr, val: u64) { self.regs[r as usize] = val; }

    #[inline]
    pub fn get32(&self, r: Gpr) -> u32 { (self.regs[r as usize] as u32) }

    #[inline]
    pub fn set32(&mut self, r: Gpr, val: u32) {
        let idx = r as usize;
        self.regs[idx] = (self.regs[idx] & 0xFFFF_FFFF_0000_0000) | (val as u64);
    }

    #[inline]
    pub fn get16(&self, r: Gpr) -> u16 { (self.regs[r as usize] as u16) }

    #[inline]
    pub fn set16(&mut self, r: Gpr, val: u16) {
        let idx = r as usize;
        self.regs[idx] = (self.regs[idx] & 0xFFFF_FFFF_FFFF_0000) | (val as u64);
    }

    #[inline]
    pub fn get8l(&self, r: Gpr) -> u8 { (self.regs[r as usize] as u8) }

    #[inline]
    pub fn set8l(&mut self, r: Gpr, val: u8) {
        let idx = r as usize;
        self.regs[idx] = (self.regs[idx] & 0xFFFF_FFFF_FFFF_FF00) | (val as u64);
    }

    #[inline]
    pub fn set_rip(&mut self, rip: u64) { self.rip = rip; }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reg_accessors() {
        let mut rf = RegFile::default();
        rf.set(Gpr::RAX, 0x1122_3344_5566_7788);
        assert_eq!(rf.get(Gpr::RAX), 0x1122_3344_5566_7788);
        rf.set32(Gpr::RAX, 0xAABB_CCDD);
        assert_eq!(rf.get(Gpr::RAX), 0x1122_3344_AABB_CCDD);
        rf.set16(Gpr::RAX, 0xEEFF);
        assert_eq!(rf.get(Gpr::RAX), 0x1122_3344_AABB_EEFF);
        rf.set8l(Gpr::RAX, 0x77);
        assert_eq!(rf.get(Gpr::RAX), 0x1122_3344_AABB_EE77);
    }
}

