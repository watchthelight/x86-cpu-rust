pub mod seg;
pub mod paging;
pub mod tlb;

pub use seg::*;
pub use paging::*;

#[cfg(test)]
mod tests {
    use super::*;

    struct Mem { data: Vec<u8> }
    impl Mem { fn new(size: usize) -> Self { Self { data: vec![0; size] } } }
    impl PhysMem for Mem {
        fn read_u32(&self, pa: u64) -> Result<u32, PhysMemError> {
            let a = pa as usize; if a+4 > self.data.len() { return Err(PhysMemError::Bad(pa)); }
            Ok(u32::from_le_bytes(self.data[a..a+4].try_into().unwrap()))
        }
        fn write_u32(&mut self, pa: u64, val: u32) -> Result<(), PhysMemError> {
            let a = pa as usize; if a+4 > self.data.len() { return Err(PhysMemError::Bad(pa)); }
            self.data[a..a+4].copy_from_slice(&val.to_le_bytes()); Ok(())
        }
    }

    fn write_u32(mem: &mut Mem, pa: u64, val: u32) { mem.write_u32(pa, val).unwrap(); }

    #[test]
    fn walk_32bit_4k_ad_bits() {
        // Layout: CR3 = 0x1000 page_dir; PDE[0]=pt at 0x2000, P/RW/US; PTE[0]=page at 0x3000, P/RW/US
        let mut mem = Mem::new(0x10000);
        let cr3 = 0x0000_1000u32;
        let pde = 0x0000_2000u32 | 0b111; // P,RW,US
        let pte = 0x0000_3000u32 | 0b111; // P,RW,US
        write_u32(&mut mem, 0x1000 + 0*4, pde);
        write_u32(&mut mem, 0x2000 + 0*4, pte);

        let mut w = Walker32 { cr3, pse: false, mem: &mut mem };
        // Read access
        let tr = w.translate(0x0000_0004, false, true, false).unwrap();
        assert_eq!(tr.phys, 0x3000 + 4);
        // PDE and PTE A set
        let pde_rd = w.mem.read_u32(0x1000).unwrap();
        let pte_rd = w.mem.read_u32(0x2000).unwrap();
        assert!( (pde_rd & (1<<5)) != 0);
        assert!( (pte_rd & (1<<5)) != 0);
        // Write sets D
        let _ = w.translate(0x0000_0008, true, true, false).unwrap();
        let pte_wr = w.mem.read_u32(0x2000).unwrap();
        assert!( (pte_wr & (1<<6)) != 0);
    }

    #[test]
    fn walk_32bit_4mb() {
        let mut mem = Mem::new(0x10000);
        let cr3 = 0x0000_1000u32;
        let pde = 0x0040_0000u32 | (1<<7) | 0b111; // PS=1, P,RW,US; base=0x0040_0000
        write_u32(&mut mem, 0x1000 + (1*4), pde);
        let mut w = Walker32 { cr3, pse: true, mem: &mut mem };
        let tr = w.translate(0x0040_1000, false, true, false).unwrap(); // dir=1
        assert_eq!(tr.phys, 0x0040_1000);
    }
}
pub use tlb::*;
