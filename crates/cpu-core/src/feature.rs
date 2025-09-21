use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureSet {
    // Baseline features
    pub sse2: bool,
    pub avx: bool,
    pub avx2: bool,
    pub avx512f: bool,
    pub avx512_bw: bool,
    pub avx512_dq: bool,
    pub avx512_vl: bool,
    pub avx512_vnni: bool,
    pub bmi1: bool,
    pub bmi2: bool,
    pub adx: bool,
    pub aes: bool,
    pub pclmulqdq: bool,
    pub sha: bool,
    pub rdrand: bool,
    pub rdseed: bool,
    pub vmx: bool,
    pub svm: bool,
    pub la57: bool,
    pub smep: bool,
    pub smap: bool,
    pub pku: bool,
}

impl Default for FeatureSet {
    fn default() -> Self {
        Self {
            sse2: true, avx: false, avx2: false, avx512f: false, avx512_bw: false, avx512_dq: false,
            avx512_vl: false, avx512_vnni: false, bmi1: true, bmi2: true, adx: false, aes: true,
            pclmulqdq: true, sha: false, rdrand: false, rdseed: false, vmx: false, svm: false,
            la57: false, smep: false, smap: false, pku: false,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum FeatureToggle { Enable, Disable }

