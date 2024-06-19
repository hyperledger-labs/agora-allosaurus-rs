use super::utils::{generate_fr, SALT};
use blsful::inner_types::Scalar;
use rand::{CryptoRng, RngCore};

/// The type of proof message. Either hidden or shared blinding
/// Shared blinding is used to link to other proofs via Schnorr.
#[derive(Copy, Clone, Debug)]
pub enum ProofMessage {
    Hidden { message: Scalar },
    SharedBlinding { message: Scalar, blinding: Scalar },
}

impl ProofMessage {
    pub fn get_message(&self) -> Scalar {
        match self {
            Self::Hidden { message } => *message,
            Self::SharedBlinding { message, .. } => *message,
        }
    }

    pub fn get_blinder(&self, rng: impl RngCore + CryptoRng) -> Scalar {
        match self {
            Self::Hidden { .. } => generate_fr(SALT, None, rng),
            Self::SharedBlinding {
                message: _,
                blinding,
            } => *blinding,
        }
    }
}
