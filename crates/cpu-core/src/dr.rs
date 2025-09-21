use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugRegs {
    pub dr0: u64,
    pub dr1: u64,
    pub dr2: u64,
    pub dr3: u64,
    pub dr6: u64,
    pub dr7: u64,
}

impl Default for DebugRegs {
    fn default() -> Self {
        Self { dr0: 0, dr1: 0, dr2: 0, dr3: 0, dr6: 0, dr7: 0 }
    }
}

