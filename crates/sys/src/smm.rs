#[derive(Debug, Default)]
pub struct SmmState {
    pub smbase: u32,
    pub inside_smm: bool,
}

