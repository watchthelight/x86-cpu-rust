#[derive(Debug, Clone, Copy)]
pub enum MicroOp {
    // Skeleton of micro-ops; will expand as ISA lands
    Nop,
    ReadGpr { dst: u8, reg: u8 },
    WriteGpr { src: u8, reg: u8 },
    Add { dst: u8, src: u8, width: u8, carry_in: bool },
}

