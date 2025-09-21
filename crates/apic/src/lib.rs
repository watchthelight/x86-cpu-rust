use serde::{Deserialize, Serialize};

bitflags::bitflags! {
    #[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ApicSpiv: u32 {
        const APIC_ENABLED = 1<<8;
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct LocalApic {
    pub id: u32,
    pub tpr: u8,
    pub ppr: u8,
    pub spiv: ApicSpiv,
}

impl LocalApic {
    pub fn is_enabled(&self) -> bool { self.spiv.contains(ApicSpiv::APIC_ENABLED) }
}
