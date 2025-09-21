use anyhow::Result;

pub trait Loader {
    fn load(&self, image: &[u8], mem: &mut dyn crate::Mem) -> Result<()>;
}

pub trait Mem {
    fn write(&mut self, addr: u64, data: &[u8]) -> Result<()>;
}

pub struct FlatLoader { pub base: u64 }
impl Loader for FlatLoader {
    fn load(&self, image: &[u8], mem: &mut dyn Mem) -> Result<()> {
        mem.write(self.base, image)?;
        Ok(())
    }
}

