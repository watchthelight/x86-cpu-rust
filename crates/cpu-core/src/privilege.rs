use crate::flags::RFlags;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Privilege {
    pub cpl: u8,
    pub iopl: u8,
}

impl Privilege {
    pub fn from_flags_and_cs(cpl: u8, flags: RFlags) -> Self {
        Self { cpl, iopl: flags.iopl() }
    }
    pub fn io_allowed(&self, iopl_required: u8) -> bool { self.cpl <= iopl_required }
}

