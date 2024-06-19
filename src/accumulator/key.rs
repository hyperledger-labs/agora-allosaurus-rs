use super::{
    utils::{generate_fr, Polynomial},
    Element,
};
use blsful::inner_types::*;
use core::convert::TryFrom;
use serde::{Deserialize, Serialize};
use zeroize::DefaultIsZeroes;

/// Represents \alpha (secret key) on page 6 in
/// <https://eprint.iacr.org/2020/777.pdf>
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct SecretKey(pub Scalar);

impl DefaultIsZeroes for SecretKey {}

impl From<SecretKey> for [u8; 32] {
    fn from(s: SecretKey) -> Self {
        s.0.to_be_bytes()
    }
}

impl TryFrom<&[u8; 32]> for SecretKey {
    type Error = &'static str;

    fn try_from(bytes: &[u8; 32]) -> Result<Self, Self::Error> {
        Option::<Scalar>::from(Scalar::from_be_bytes(bytes))
            .ok_or("Invalid byte sequence")
            .map(SecretKey)
    }
}

impl SecretKey {
    const BYTES: usize = 32;

    /// Create a new secret key
    pub fn new(seed: Option<&[u8]>) -> Self {
        // Giuseppe Vitto, Alex Biryukov = VB
        // Accumulator = ACC
        Self(generate_fr(b"VB-ACC-KEYGEN-SALT-", seed, rand::rngs::OsRng))
    }

    /// Return the raw byte representation of the key
    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        self.0.to_be_bytes()
    }

    /// Compute the batch add elements value
    pub fn batch_additions(&self, additions: &[Element]) -> Element {
        Element(
            additions
                .iter()
                .map(|v| v.0 + self.0)
                .fold(Scalar::ONE, |a, y| a * y),
        )
    }

    /// Compute the batch remove elements value
    pub fn batch_deletions(&self, deletions: &[Element]) -> Element {
        Element(self.batch_additions(deletions).0.invert().unwrap())
    }

    /// Create the Batch Polynomial coefficients
    pub fn create_coefficients(
        &self,
        additions: &[Element],
        deletions: &[Element],
    ) -> Vec<Element> {
        // vD(x) = ∑^{m}_{s=1}{ ∏ 1..s {yD_i + alpha}^-1 ∏ 1 ..s-1 {yD_j - x}
        let one = Scalar::ONE;
        let m1 = -one;
        let mut v_d = Polynomial::with_capacity(deletions.len());
        for s in 0..deletions.len() {
            // ∏ 1..s (yD_i + alpha)^-1
            let c = self.batch_deletions(&deletions[0..s + 1]).0;
            let mut poly = Polynomial::with_capacity(deletions.len());
            poly.push(one);
            // ∏ 1..(s-1) (yD_j - x)
            for j in deletions.iter().take(s) {
                poly *= &[j.0, m1];
            }
            poly *= c;
            v_d += poly;
        }

        //v_d(x) * ∏ 1..n (yA_i + alpha)
        v_d *= self.batch_additions(additions).0;

        // vA(x) = ∑^n_{s=1}{ ∏ 1..s-1 {yA_i + alpha} ∏ s+1..n {yA_j - x} }
        let mut v_a = Polynomial::with_capacity(additions.len());
        for s in 0..additions.len() {
            // ∏ 1..s-1 {yA_i + alpha}
            let c = if s == 0 {
                one
            } else {
                self.batch_additions(&additions[0..s]).0
            };
            let mut poly = Polynomial::with_capacity(additions.len());
            poly.push(one);
            // ∏ s+1..n {yA_j - x}
            for j in additions.iter().skip(s + 1) {
                poly *= &[j.0, m1];
            }
            poly *= c;
            v_a += poly;
        }
        // vA - vD
        v_a -= v_d;

        v_a.0.iter().map(|b| Element(*b)).collect()
    }
}

/// Represents \overline{Q} = \overline{P}*\alpha (public key) on page 6 in
/// <https://eprint.iacr.org/2020/777.pdf>
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PublicKey(pub G2Projective);

impl core::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PublicKey {{ {} }}", self.0)
    }
}

impl From<PublicKey> for G2Projective {
    fn from(p: PublicKey) -> Self {
        p.0
    }
}

impl From<G2Projective> for PublicKey {
    fn from(g: G2Projective) -> Self {
        Self(g)
    }
}

impl PublicKey {
    const BYTES: usize = 96;

    /// Return the byte representation for this public key
    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let mut d = [0u8; Self::BYTES];
        d.copy_from_slice(self.0.to_bytes().as_ref());
        d
    }
}

impl From<&SecretKey> for PublicKey {
    fn from(sk: &SecretKey) -> Self {
        Self(G2Projective::GENERATOR * sk.0)
    }
}

impl TryFrom<&[u8; 96]> for PublicKey {
    type Error = &'static str;

    fn try_from(bytes: &[u8; 96]) -> Result<Self, Self::Error> {
        Option::<G2Projective>::from(G2Projective::from_compressed(bytes))
            .map(Self)
            .ok_or("invalid byte sequence")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blsful::inner_types::G1Projective;

    #[test]
    fn batch_test() {
        let key = SecretKey::new(None);
        let data = vec![Element::hash(b"value1"), Element::hash(b"value2")];
        let add = key.batch_additions(data.as_slice());
        let del = key.batch_deletions(data.as_slice());
        let res = add.0 * del.0;
        assert_eq!(res, Scalar::ONE);
        assert_eq!(G1Projective::GENERATOR * res, G1Projective::GENERATOR);
    }

    #[test]
    fn coefficient_test() {
        let key = SecretKey::new(Some(b"1234567890"));
        let data = vec![
            Element::hash(b"1"),
            Element::hash(b"2"),
            Element::hash(b"3"),
            Element::hash(b"4"),
            Element::hash(b"5"),
        ];
        let coefficients = key.create_coefficients(&data[0..2], &data[2..5]);
        assert_eq!(coefficients.len(), 3);
    }
}
