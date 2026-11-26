use super::{Name, PROTO};
use serde::{Deserialize, Serialize};

pub const PATTERN_PAIR: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
pub const PATTERN_RESUME: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
pub const HS_MSG_MAX: usize = 1_024;
pub const SAS_CONTEXT: &str = "csync 2026-11 pairing sas v1";
pub const PAIR_TIMEOUT_S: u64 = 120;

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HsMode {
    Pair = 1,
    Resume = 2,
}
impl HsMode {
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Pair),
            2 => Some(Self::Resume),
            _ => None,
        }
    }
}

pub fn prologue(mode: HsMode) -> [u8; 11] {
    let mut p = *b"csync/1\0\0\0\0";
    p[8] = mode as u8;
    p[9..11].copy_from_slice(&PROTO.to_le_bytes());
    p
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    Host,
    Guest,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct HsHello {
    pub proto: u16,
    pub role: Role,
    pub name: Name,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum PairStep {
    HostAccepted,
    GuestConfirmed,
    Rejected,
}

pub fn sas(handshake_hash: &[u8]) -> [u8; 8] {
    const A: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let k = blake3::derive_key(SAS_CONTEXT, handshake_hash);
    let mut v = u64::from_be_bytes([0, 0, 0, k[0], k[1], k[2], k[3], k[4]]);
    let mut out = [0u8; 8];
    for c in out.iter_mut().rev() {
        *c = A[(v & 31) as usize];
        v >>= 5;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    fn sas_bits(code: &[u8; 8]) -> u64 {
        code.iter().fold(0u64, |acc, c| {
            (acc << 5) | A.iter().position(|a| a == c).unwrap() as u64
        })
    }

    #[test]
    fn sas_encodes_first_40_bits_of_derived_key() {
        for h in [
            [0u8; 32],
            [0xa5; 32],
            *blake3::hash(b"transcript").as_bytes(),
        ] {
            let code = sas(&h);
            assert_eq!(code, sas(&h));
            let k = blake3::derive_key(SAS_CONTEXT, &h);
            let want = u64::from_be_bytes([0, 0, 0, k[0], k[1], k[2], k[3], k[4]]);
            assert_eq!(sas_bits(&code), want);
        }
    }

    #[test]
    fn sas_is_domain_separated() {
        let h = [7u8; 32];
        let plain = blake3::hash(&h);
        let k = blake3::derive_key(SAS_CONTEXT, &h);
        assert_ne!(&k, plain.as_bytes());
        assert_ne!(sas(&h), sas(&[8u8; 32]));
    }

    #[test]
    fn prologue_binds_mode_and_proto() {
        let p = prologue(HsMode::Pair);
        let r = prologue(HsMode::Resume);
        assert_ne!(p, r);
        assert_eq!(&p[..8], b"csync/1\0");
        assert_eq!(p[8], 1);
        assert_eq!(r[8], 2);
        assert_eq!(u16::from_le_bytes([p[9], p[10]]), PROTO);
        assert_eq!(HsMode::from_u8(p[8]), Some(HsMode::Pair));
        assert_eq!(HsMode::from_u8(0), None);
        assert_eq!(HsMode::from_u8(3), None);
    }
}
