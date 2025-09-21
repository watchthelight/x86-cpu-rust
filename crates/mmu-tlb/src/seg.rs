use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Mode {
    Real,
    V8086,
    Protected,
    Long,
    Compat,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct DescAttr {
    pub base: u64,
    pub limit: u32,
    pub present: bool,
    pub dpl: u8,
    pub executable: bool,
    pub conforming: bool,
    pub writable: bool,
    pub readable: bool,
    pub expand_down: bool,
    pub default_db: bool,
    pub long: bool,
    pub gran_4k: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum SegFault {
    #[error("segment not present")] NotPresent,
    #[error("limit violation")] Limit,
    #[error("privilege violation")] Privilege,
}

pub fn check_data_access(attr: DescAttr, cpl: u8, effective_rpl: u8, offset: u32, size: u32) -> Result<(), SegFault> {
    if !attr.present { return Err(SegFault::NotPresent); }
    // DPL check for data segments: max(RPL, CPL) <= DPL
    let eff = effective_rpl.max(cpl);
    if eff > attr.dpl { return Err(SegFault::Privilege); }
    let limit = if attr.gran_4k { ((attr.limit as u64) << 12) | 0xFFF } else { attr.limit as u64 };
    let start = offset as u64;
    let end = start.wrapping_add(size as u64 - 1);
    if attr.expand_down {
        // Expand-down: valid range is (limit .. max] (strictly greater than limit)
        let max_off = if attr.default_db { 0xFFFF_FFFFu64 } else { 0xFFFFu64 };
        if start <= limit || end <= limit || end > max_off { return Err(SegFault::Limit); }
    } else {
        if end > limit { return Err(SegFault::Limit); }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn expand_down_limits() {
        let attr = DescAttr { base: 0, limit: 0x0FFF, present: true, dpl: 3, executable: false, conforming: false, writable: true, readable: true, expand_down: true, default_db: false, long: false, gran_4k: false };
        // Access at <= limit is invalid
        assert!(check_data_access(attr, 3, 3, 0x0FFF, 1).is_err());
        // Access just above limit is valid
        assert!(check_data_access(attr, 3, 3, 0x1000, 1).is_ok());
        // Access far above still valid within max
        assert!(check_data_access(attr, 3, 3, 0x2000, 1).is_ok());
    }
}
