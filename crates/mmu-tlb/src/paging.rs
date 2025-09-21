use serde::{Deserialize, Serialize};

bitflags::bitflags! {
    #[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
    pub struct PteFlags: u64 {
        const P = 1<<0;   // Present
        const RW = 1<<1;  // Read/Write
        const US = 1<<2;  // User/Supervisor
        const PWT = 1<<3; // Write-through
        const PCD = 1<<4; // Cache-disable
        const A = 1<<5;   // Accessed
        const D = 1<<6;   // Dirty
        const PS = 1<<7;  // Page Size (PD/PT meaning)
        const G = 1<<8;   // Global
        const NX = 1<<63; // No-execute (if EFER.NXE)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AddressWidth { A32, A36, A39, A48, A57 }

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct TranslateResult {
    pub phys: u64,
    pub flags: PteFlags,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PageFaultKind { 
    #[error("not present")] NotPresent, 
    #[error("protection violation")] Protection, 
}

#[derive(Debug, thiserror::Error)]
#[error("page fault: {kind:?} at lin={lin:#x}")]
pub struct PageFault { pub lin: u64, pub kind: PageFaultKind, pub code: u32 }

pub trait PageWalker {
    fn translate(&mut self, lin: u64, write: bool, user: bool, exec: bool) -> Result<TranslateResult, PageFault>;
}

#[derive(Debug, thiserror::Error)]
pub enum PhysMemError { #[error("bad phys addr {0:#x}")] Bad(u64) }

pub trait PhysMem {
    fn read_u32(&self, pa: u64) -> Result<u32, PhysMemError>;
    fn write_u32(&mut self, pa: u64, val: u32) -> Result<(), PhysMemError>;
}

pub struct Walker32<'a, M: PhysMem> {
    pub cr3: u32,
    pub pse: bool,
    pub mem: &'a mut M,
}

impl<'a, M: PhysMem> Walker32<'a, M> {
    fn pf(lin: u64, present: bool, write: bool, user: bool) -> PageFault {
        let mut code = 0u32;
        if !present { code |= 1<<0; }
        if write { code |= 1<<1; }
        if user { code |= 1<<2; }
        PageFault { lin, kind: if present { PageFaultKind::Protection } else { PageFaultKind::NotPresent }, code }
    }
}

impl<'a, M: PhysMem> PageWalker for Walker32<'a, M> {
    fn translate(&mut self, lin: u64, write: bool, user: bool, _exec: bool) -> Result<TranslateResult, PageFault> {
        let cr3_base = (self.cr3 as u64) & 0xFFFFF000;
        let dir = ((lin >> 22) & 0x3FF) as u64;
        let tbl = ((lin >> 12) & 0x3FF) as u64;
        let off = lin & 0xFFF;
        let pde_pa = cr3_base + dir*4;
        let mut pde = self.mem.read_u32(pde_pa).map_err(|_| Walker32::<M>::pf(lin, false, write, user))?;
        let pde_p = (pde & 1) != 0;
        if !pde_p { return Err(Walker32::<M>::pf(lin, false, write, user)); }
        // Set A bit on PDE
        if (pde & (1<<5)) == 0 { pde |= 1<<5; self.mem.write_u32(pde_pa, pde).map_err(|_| Walker32::<M>::pf(lin, true, write, user))?; }

        if self.pse && (pde & (1<<7)) != 0 {
            // 4MiB page
            let base = (pde as u64) & 0xFFC00000;
            if write && (pde & (1<<1)) == 0 { return Err(Walker32::<M>::pf(lin, true, write, user)); }
            if user && (pde & (1<<2)) == 0 { return Err(Walker32::<M>::pf(lin, true, write, user)); }
            // Dirty bit set on write
            if write && (pde & (1<<6)) == 0 { let new = pde | (1<<6); self.mem.write_u32(pde_pa, new).map_err(|_| Walker32::<M>::pf(lin, true, write, user))?; }
            let phys = base | (lin & 0x3FFFFF);
            let mut flags = PteFlags::empty();
            flags.set(PteFlags::RW, (pde & (1<<1)) != 0);
            flags.set(PteFlags::US, (pde & (1<<2)) != 0);
            flags.insert(PteFlags::P);
            return Ok(TranslateResult { phys, flags });
        }

        // 4KiB page
        let pt_base = (pde as u64) & 0xFFFFF000;
        let pte_pa = pt_base + tbl*4;
        let mut pte = self.mem.read_u32(pte_pa).map_err(|_| Walker32::<M>::pf(lin, false, write, user))?;
        let pte_p = (pte & 1) != 0;
        if !pte_p { return Err(Walker32::<M>::pf(lin, false, write, user)); }

        // Access checks: combining PDE/PTE RW/US
        let rw = ((pde | pte) & (1<<1)) != 0;
        let us = ((pde | pte) & (1<<2)) != 0;
        if write && !rw { return Err(Walker32::<M>::pf(lin, true, write, user)); }
        if user && !us { return Err(Walker32::<M>::pf(lin, true, write, user)); }

        // Set A/D bits
        if (pte & (1<<5)) == 0 { pte |= 1<<5; self.mem.write_u32(pte_pa, pte).map_err(|_| Walker32::<M>::pf(lin, true, write, user))?; }
        if write && (pte & (1<<6)) == 0 { let new = pte | (1<<6); self.mem.write_u32(pte_pa, new).map_err(|_| Walker32::<M>::pf(lin, true, write, user))?; }

        let base = (pte as u64) & 0xFFFFF000;
        let phys = base | off;
        let mut flags = PteFlags::empty();
        flags.set(PteFlags::RW, rw);
        flags.set(PteFlags::US, us);
        flags.insert(PteFlags::P);
        Ok(TranslateResult { phys, flags })
    }
}
