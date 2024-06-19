use super::utils::{generate_fr, SALT};
use blsful::inner_types::Scalar;
use rand::{CryptoRng, RngCore};

/// The type of proof message. Either hidden or shared blinding
/// Shared blinding is used to link to other proofs via Schnorr.
#[derive(Copy, Clone, Debug)]
pub enum ProofMessage {
    /// Hidden message
    Hidden {
        /// The message to hide
        message: Scalar,
    },
    /// Shared blinding message
    SharedBlinding {
        /// The message to hide
        message: Scalar,
        /// The blinding factor
        blinder: Scalar,
    },
}

impl ProofMessage {
    /// Get the message
    pub fn get_message(&self) -> Scalar {
        match self {
            Self::Hidden { message } => *message,
            Self::SharedBlinding { message, .. } => *message,
        }
    }

    /// Get the blinding
    pub fn get_blinder(&self, rng: impl RngCore + CryptoRng) -> Scalar {
        match self {
            Self::Hidden { .. } => generate_fr(SALT, None, rng),
            Self::SharedBlinding {
                message: _,
                blinder: blinding,
            } => *blinding,
        }
    }
}
