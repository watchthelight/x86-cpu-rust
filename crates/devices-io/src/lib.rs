use std::collections::BTreeMap;

#[derive(Debug, thiserror::Error)]
pub enum IoError { #[error("io port {0:#x} not mapped")] Unmapped(u16) }

pub trait IoDevice: Send + Sync {
    fn inb(&self, port: u16) -> Result<u8, IoError> { Err(IoError::Unmapped(port)) }
    fn inw(&self, port: u16) -> Result<u16, IoError> { Err(IoError::Unmapped(port)) }
    fn inl(&self, port: u16) -> Result<u32, IoError> { Err(IoError::Unmapped(port)) }
    fn outb(&self, port: u16, _val: u8) -> Result<(), IoError> { Err(IoError::Unmapped(port)) }
    fn outw(&self, port: u16, _val: u16) -> Result<(), IoError> { Err(IoError::Unmapped(port)) }
    fn outl(&self, port: u16, _val: u32) -> Result<(), IoError> { Err(IoError::Unmapped(port)) }
}

#[derive(Default)]
pub struct IoBus { map: BTreeMap<u16, Box<dyn IoDevice>> }

impl IoBus {
    pub fn new() -> Self { Self { map: BTreeMap::new() } }
    pub fn map(&mut self, base: u16, dev: Box<dyn IoDevice>) { self.map.insert(base, dev); }
}
