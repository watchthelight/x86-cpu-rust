#[cfg(test)]
mod tests {
    use cpu_core::flags::{alu_add_flags, alu_sub_flags};
    use cpu_core::types::Width;
    
    #[test]
    fn add_sub_roundtrip_32() {
        let a = 0x1122_3344u64; let b = 0x5566_7788u64;
        let f = alu_add_flags(Width::W32, a, b, false);
        assert_eq!(f.cf, false);
        let (fs, r) = alu_sub_flags(Width::W32, (a+b) & 0xFFFF_FFFF, b, false);
        assert_eq!(r as u32, a as u32);
        assert_eq!(fs.zf, false);
    }
}
