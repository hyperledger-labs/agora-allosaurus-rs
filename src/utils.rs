use crate::accumulator::{Element, PublicKey};
use blsful::{inner_types::*, vsss_rs::Polynomial as VSSSPolynomial};
use merlin::Transcript;
use serde::{Deserialize, Serialize};

/// The security parameter for the system
pub(crate) const SECURITY_BYTES: usize = 128 / 8;

/// The UserID type
pub type UserID = Element;

/// ALLOSAUR public keys
#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
pub struct PublicKeys {
    /// The witness public key
    pub witness_key: PublicKey,
    /// The signature public key
    pub sign_key: PublicKey,
}

/// Group parameters
#[derive(Copy, Clone, Debug, Deserialize, Serialize, Eq, PartialEq, Hash)]
pub struct AccParams {
    pub(crate) p1: G1Projective,
    pub(crate) p2: G2Projective,
    pub(crate) k0: G1Projective,
    pub(crate) k1: G1Projective,
    pub(crate) k2: G2Projective,
    pub(crate) x1: G1Projective,
    pub(crate) y1: G1Projective,
    pub(crate) z1: G1Projective,
}

impl Default for AccParams {
    fn default() -> AccParams {
        const DST_G1: &[u8] = b"BLS12381G1_XMD:SHA-256_SSWU_RO_";
        const DST_G2: &[u8] = b"BLS12381G2_XMD:SHA-256_SSWU_RO_";
        let mut array = [0xFFu8; 32];
        let k0 = G1Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(&array, DST_G1);
        array[0] = 0xFE;
        let k1 = G1Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(&array, DST_G1);
        array[0] = 0xFD;
        let k2 = G2Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(&array, DST_G2);
        array[0] = 0xFC;
        let x1 = G1Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(&array, DST_G1);
        array[0] = 0xFB;
        let y1 = G1Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(&array, DST_G1);
        array[0] = 0xFA;
        let z1 = G1Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(&array, DST_G1);
        AccParams {
            p1: G1Projective::GENERATOR,
            p2: G2Projective::GENERATOR,
            k0,
            k1,
            k2,
            x1,
            y1,
            z1,
        }
    }
}

impl AccParams {
    // read-only
    /// Get the p1 Generator
    pub fn get_p1(&self) -> G1Projective {
        self.p1
    }
    /// Get the p2 Generator
    pub fn get_p2(&self) -> G2Projective {
        self.p2
    }
    /// Get the k0 Generator
    pub fn get_k0(&self) -> G1Projective {
        self.k0
    }
    /// Get the k1 Generator
    pub fn get_k1(&self) -> G1Projective {
        self.k1
    }
    /// Get the k2 Generator
    pub fn get_k2(&self) -> G2Projective {
        self.k2
    }
    /// Get the x1 Generator
    pub fn get_x1(&self) -> G1Projective {
        self.x1
    }
    /// Get the y1 Generator
    pub fn get_y1(&self) -> G1Projective {
        self.y1
    }
    /// Get the z1 Generator
    pub fn get_z1(&self) -> G1Projective {
        self.z1
    }

    /// Add these proof params to the transcript
    pub fn add_to_transcript(&self, transcript: &mut Transcript) {
        transcript.append_message(b"Proof Param K", self.k1.to_bytes().as_ref());
        transcript.append_message(b"Proof Param X", self.x1.to_bytes().as_ref());
        transcript.append_message(b"Proof Param Y", self.y1.to_bytes().as_ref());
        transcript.append_message(b"Proof Param Z", self.z1.to_bytes().as_ref());
    }
}

// Divides a secret into Shamir shares with a given threshold
// The returned vector consists of (value, share)
// such that the there is a degree-(threshold) polynomial p such that
// p(value) = share
pub(crate) fn shamir_share(
    threshold: usize,
    num_shares: usize,
    secret: Scalar,
) -> Vec<(Scalar, Scalar)> {
    let mut poly = Vec::<Scalar>::create(threshold);
    poly[0] = secret;
    poly[1..].iter_mut().for_each(|x| *x = Element::random().0);

    let mut shares = vec![(Scalar::ZERO, Scalar::ZERO); num_shares];
    shares.iter_mut().enumerate().for_each(|(i, x)| {
        x.0 = Scalar::from((i + 1) as u64);
        x.1 = poly.evaluate(x.0, threshold);
    });
    shares
}

// Produces just the coefficients necessary to rebuild from these shares
// These save on computation because the user can build them once
pub(crate) fn shamir_coefficients<T>(
    threshold: usize,
    shares: &[(Scalar, T)],
) -> (Vec<Scalar>, Option<Vec<Scalar>>) {
    let product = shares[0..threshold]
        .iter()
        .fold(Scalar::ONE, |a, y| a * y.0);
    let mut coefficients = vec![product; threshold];
    // Compact formula for coefficients to rebuild Shamir shares
    for i in 0..threshold {
        for ii in 0..threshold {
            if i == ii {
                coefficients[i] *= shares[i].0.invert().expect("to not be zero");
            } else {
                coefficients[i] *= (shares[ii].0 - shares[i].0)
                    .invert()
                    .expect("to not be zero");
            }
        }
    }

    // add a check
    // This is just a shift of the old shares, so there's less arithmetic to compute it
    if shares.len() > threshold {
        let mut check_coefficients = coefficients.clone();
        let adjustment = shares[threshold].0 * shares[0].0.invert().expect("to not be zero");
        check_coefficients[0] = product * shares[0].0;
        for i in 1..threshold {
            check_coefficients[i] *= adjustment
                * (shares[0].0 - shares[i].0)
                * (shares[threshold].0 - shares[i].0)
                    .invert()
                    .expect("to not be zero");
            check_coefficients[0] *= (shares[i].0 - shares[threshold].0)
                .invert()
                .expect("to not be zero");
        }

        return (coefficients, Some(check_coefficients));
    }
    (coefficients, None)
}

// Multiplies the coefficients by the returned shares to produce the output at 0
pub(crate) fn shamir_rebuild_scalar(
    shares: &[(Scalar, Scalar)],
    coefficients: &[Scalar],
    check_coefficients: &Option<Vec<Scalar>>,
) -> Option<Scalar> {
    let mut result = Scalar::ZERO;
    for i in 0..coefficients.len() {
        result += shares[i].1 * coefficients[i];
    }
    match check_coefficients {
        Some(checks) => {
            let threshold = coefficients.len();
            let mut check_result = checks[0] * shares[threshold].1;
            for i in 1..threshold {
                check_result += checks[i] * shares[i].1;
            }
            if check_result == result {
                return Some(result);
            }
            return None;
        }
        None => {}
    }
    Some(result)
}

// Multiplies the coefficients by the returned shares of an elliptic curve point to produce the output at 0
// If check coefficients are given, the user will evaluate on the check coefficients and if they do not
// match what the other shares, the user returns nothing.
pub(crate) fn shamir_rebuild_point(
    shares: &[(Scalar, G1Projective)],
    coefficients: &[Scalar],
    check_coefficients: &Option<Vec<Scalar>>,
) -> Option<G1Projective> {
    let mut result = G1Projective::IDENTITY;
    for i in 0..coefficients.len() {
        result += shares[i].1 * coefficients[i];
    }
    match check_coefficients {
        Some(checks) => {
            let threshold = coefficients.len();
            let mut check_result = shares[threshold].1 * checks[0];
            for i in 1..threshold {
                check_result += shares[i].1 * checks[i];
            }
            if check_result == result {
                return Some(result);
            }
            return None;
        }
        None => {}
    }
    Some(result)
}

pub(crate) fn g1(b: &[u8]) -> Result<G1Projective, &'static str> {
    let buf = <[u8; 48]>::try_from(b).map_err(|_| "Proof serialization error")?;
    Option::<G1Projective>::from(G1Projective::from_compressed(&buf))
        .ok_or("Proof serialization error")
}

pub(crate) fn sc(b: &[u8]) -> Result<Scalar, &'static str> {
    let buf = <[u8; 32]>::try_from(b).map_err(|_| "Proof serialization error")?;
    Option::<Scalar>::from(Scalar::from_be_bytes(&buf)).ok_or("Proof serialization error")
}
