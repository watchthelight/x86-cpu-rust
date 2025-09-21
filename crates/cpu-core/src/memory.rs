use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum MemError {
    #[error("address {0:#x} out of range")] OutOfRange(u64),
}

pub trait Memory {
    fn read(&self, addr: u64, buf: &mut [u8]) -> Result<(), MemError>;
    fn write(&mut self, addr: u64, data: &[u8]) -> Result<(), MemError>;
}

#[derive(Clone, Serialize, Deserialize)]
pub struct FlatMem {
    data: Vec<u8>,
}

impl FlatMem {
    pub fn new(size: usize) -> Self { Self { data: vec![0u8; size] } }
}

impl Memory for FlatMem {
    fn read(&self, addr: u64, buf: &mut [u8]) -> Result<(), MemError> {
        let a = addr as usize;
        let end = a.checked_add(buf.len()).ok_or(MemError::OutOfRange(addr))?;
        self.data.get(a..end).ok_or(MemError::OutOfRange(addr))?.iter().enumerate().for_each(|(i, b)| buf[i] = *b);
        Ok(())
    }
    fn write(&mut self, addr: u64, data: &[u8]) -> Result<(), MemError> {
        let a = addr as usize;
        let end = a.checked_add(data.len()).ok_or(MemError::OutOfRange(addr))?;
        let slice = self.data.get_mut(a..end).ok_or(MemError::OutOfRange(addr))?;
        slice.copy_from_slice(data);
        Ok(())
    }
}

