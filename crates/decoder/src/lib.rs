use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AddrSize { A16, A32, A64 }

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum OpSize { O16, O32, O64 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodedInst {
    pub len: u8,
    pub opcode: u32,
    pub rep: bool,
    pub lock: bool,
    pub addr_size: AddrSize,
    pub op_size: OpSize,
}

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("invalid instruction encoding")] Invalid,
}

pub trait Decoder {
    fn decode(&mut self, bytes: &[u8], ip: u64, is64: bool) -> Result<DecodedInst, DecodeError>;
}

pub struct NullDecoder;
impl Decoder for NullDecoder {
    fn decode(&mut self, _bytes: &[u8], _ip: u64, _is64: bool) -> Result<DecodedInst, DecodeError> {
        Err(DecodeError::Invalid)
    }
}

#[cfg(feature = "iced")]
mod iced_impl {
    use super::*;
    use iced_x86::{Decoder as IcedDecoder, DecoderOptions, Instruction};

    pub struct IcedWrapper;
    impl super::Decoder for IcedWrapper {
        fn decode(&mut self, bytes: &[u8], ip: u64, is64: bool) -> Result<DecodedInst, DecodeError> {
            let mut d = if is64 { IcedDecoder::with_ip(64, bytes, ip, DecoderOptions::NONE) } else { IcedDecoder::with_ip(32, bytes, ip, DecoderOptions::NONE) };
            let mut inst = Instruction::default();
            d.decode_out(&mut inst);
            if inst.code() == iced_x86::Code::INVALID { return Err(DecodeError::Invalid); }
            Ok(DecodedInst {
                len: inst.len() as u8,
                opcode: inst.code() as u32,
                rep: inst.has_rep_prefix() || inst.has_repe_prefix() || inst.has_repne_prefix(),
                lock: inst.has_lock_prefix(),
                addr_size: if is64 { AddrSize::A64 } else { AddrSize::A32 },
                op_size: if inst.is_broadcast() { OpSize::O64 } else { OpSize::O32 },
            })
        }
    }
}

