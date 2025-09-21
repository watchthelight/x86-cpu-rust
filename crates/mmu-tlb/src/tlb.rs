use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::paging::{TranslateResult, PageFault, PteFlags};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Pcid(pub u16);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TlbKey { pub pcid: Option<Pcid>, pub page: u64 }

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct TlbEntry { pub phys_page: u64, pub flags: PteFlags }

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Tlb { map: HashMap<TlbKey, TlbEntry> }

impl Tlb {
    pub fn new() -> Self { Self { map: HashMap::new() } }
    pub fn lookup(&self, key: TlbKey) -> Option<TlbEntry> { self.map.get(&key).copied() }
    pub fn insert(&mut self, key: TlbKey, val: TlbEntry) { self.map.insert(key, val); }
    pub fn invlpg(&mut self, key: TlbKey) { self.map.remove(&key); }
    pub fn flush_pcid(&mut self, pcid: Pcid) {
        self.map.retain(|k, _| k.pcid.map(|p| p != pcid).unwrap_or(true))
    }
    pub fn flush_all(&mut self) { self.map.clear(); }
}

pub fn translate_cached(tlb: &mut Tlb, key: TlbKey, lin: u64, walker: &mut impl crate::paging::PageWalker, write: bool, user: bool, exec: bool) -> Result<TranslateResult, PageFault> {
    if let Some(ent) = tlb.lookup(key) {
        let phys = (ent.phys_page << 12) | (lin & 0xFFF);
        return Ok(TranslateResult { phys, flags: ent.flags });
    }
    let tr = walker.translate(lin, write, user, exec)?;
    tlb.insert(key, TlbEntry { phys_page: tr.phys >> 12, flags: tr.flags });
    Ok(tr)
}
