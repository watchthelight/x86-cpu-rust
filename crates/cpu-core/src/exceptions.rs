use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Vector {
    DE = 0,  // Divide Error
    DB = 1,  // Debug
    NMI = 2, // Non-maskable
    BP = 3,  // Breakpoint
    OF = 4,  // Overflow
    BR = 5,  // BOUND Range Exceeded
    UD = 6,  // Invalid Opcode
    NM = 7,  // Device Not Available
    DF = 8,  // Double Fault
    TS = 10, // Invalid TSS
    NP = 11, // Segment Not Present
    SS = 12, // Stack Fault
    GP = 13, // General Protection
    PF = 14, // Page Fault
    MF = 16, // x87 FP Exception-Pending
    AC = 17, // Alignment Check
    XM = 19, // SIMD FP Exception
    VE = 20, // Virtualization Exception
    CP = 21, // Control Protection (CET)
    HV = 28, // Hypervisor Injection (placeholder)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Exception {
    pub vector: Vector,
    pub error_code: Option<u32>,
}

impl Exception {
    pub fn new(vector: Vector, error_code: Option<u32>) -> Self { Self { vector, error_code } }
}

