use super::utils::hash_to_g1;
use super::{
    utils::{generate_fr, SALT},
    SecretKey,
};
use blsful::inner_types::*;
use core::fmt::{self, Display, Formatter};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};

/// An element in the accumulator
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Element(pub Scalar);

impl Hash for Element {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_be_bytes().hash(state)
    }
}

impl Display for Element {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Element {{ {} }}", self.0)
    }
}

impl TryFrom<&[u8; 32]> for Element {
    type Error = &'static str;

    fn try_from(value: &[u8; 32]) -> Result<Self, Self::Error> {
        Option::<Scalar>::from(Scalar::from_be_bytes(value))
            .map(Self)
            .ok_or("invalid byte sequence")
    }
}

impl Element {
    const BYTES: usize = 32;

    /// Return the multiplicative identity element
    pub fn one() -> Self {
        Self(Scalar::ONE)
    }

    /// Return the byte representation
    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        self.0.to_be_bytes()
    }

    /// Construct an element by hashing the specified bytes
    pub fn hash(d: &[u8]) -> Self {
        Self(generate_fr(SALT, Some(d), rand::rngs::OsRng))
    }

    /// Compute an element from a Merlin Transcript
    pub fn from_transcript(label: &'static [u8], transcript: &mut merlin::Transcript) -> Self {
        let mut okm = [0u8; 64];
        transcript.challenge_bytes(label, &mut okm);
        Self(Scalar::from_bytes_wide(&okm))
    }

    /// Construct a random element
    pub fn random() -> Self {
        Self(generate_fr(SALT, None, rand::rngs::OsRng))
    }
}

/// A coefficent for updating witnesses
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Coefficient(pub G1Projective);

impl Display for Coefficient {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Coefficient {{ {} }}", self.0)
    }
}

impl From<Coefficient> for G1Projective {
    fn from(c: Coefficient) -> Self {
        c.0
    }
}

impl From<G1Projective> for Coefficient {
    fn from(g: G1Projective) -> Self {
        Self(g)
    }
}

impl TryFrom<&[u8; 48]> for Coefficient {
    type Error = &'static str;

    fn try_from(value: &[u8; 48]) -> Result<Self, Self::Error> {
        Option::<G1Projective>::from(G1Projective::from_compressed(value))
            .map(Self)
            .ok_or("invalid byte sequence")
    }
}

impl Coefficient {
    const BYTES: usize = 48;

    /// The byte representation of this coefficient
    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        self.0.to_compressed()
    }
}

/// Represents a Universal Bilinear Accumulator.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Accumulator(pub G1Projective);

impl Display for Accumulator {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Accumulator {{ {} }}", self.0)
    }
}

impl From<Accumulator> for G1Projective {
    fn from(a: Accumulator) -> Self {
        a.0
    }
}

impl From<G1Projective> for Accumulator {
    fn from(g: G1Projective) -> Self {
        Self(g)
    }
}

impl TryFrom<&[u8; 48]> for Accumulator {
    type Error = &'static str;

    fn try_from(value: &[u8; 48]) -> Result<Self, Self::Error> {
        Option::<G1Projective>::from(G1Projective::from_compressed(value))
            .map(Self)
            .ok_or("invalid byte sequence")
    }
}

impl Default for Accumulator {
    fn default() -> Self {
        Self(G1Projective::GENERATOR)
    }
}

impl Accumulator {
    /// The number of bytes in an accumulator
    pub const BYTES: usize = 48;

    /// Create a random accumulator
    pub fn random(mut rng: impl RngCore + CryptoRng) -> Self {
        let mut buffer = [0u8; 64];
        rng.fill_bytes(&mut buffer);
        Self(hash_to_g1(buffer))
    }

    /// Initialize a new accumulator prefilled with entries
    /// Each member is assumed to be hashed
    pub fn with_elements(key: &SecretKey, m: &[Element]) -> Self {
        let y = key.batch_additions(m.as_ref());
        Self(G1Projective::GENERATOR * y.0)
    }

    /// Add many members
    pub fn add_elements(&self, key: &SecretKey, m: &[Element]) -> Self {
        let y = key.batch_additions(m.as_ref());
        Self(self.0 * y.0)
    }

    /// Add many members
    pub fn add_elements_assign(&mut self, key: &SecretKey, m: &[Element]) {
        self.0 *= key.batch_additions(m).0;
    }

    /// Add a value to the accumulator, the value will be hashed to a prime number first
    pub fn add(&self, key: &SecretKey, value: Element) -> Self {
        Self(self.0 * (key.0 + value.0))
    }

    /// Add a value an update this accumulator
    pub fn add_assign(&mut self, key: &SecretKey, value: Element) {
        self.0 *= key.0 + value.0;
    }

    /// Remove a value from the accumulator and return
    /// a new accumulator without `value`
    pub fn remove(&self, key: &SecretKey, value: Element) -> Self {
        let v = (key.0 + value.0).invert().unwrap();
        Self(self.0 * v)
    }

    /// Remove a value from the accumulator if it exists
    pub fn remove_assign(&mut self, key: &SecretKey, value: Element) {
        let v = (key.0 + value.0).invert().unwrap();
        self.0 *= v;
    }

    /// Remove multiple values and return
    /// a new accumulator
    pub fn remove_elements(&self, key: &SecretKey, deletions: &[Element]) -> Self {
        let v = key.batch_deletions(deletions);
        Self(self.0 * v.0)
    }

    /// Remove multiple values
    pub fn remove_elements_assign(&mut self, key: &SecretKey, deletions: &[Element]) {
        self.0 *= key.batch_deletions(deletions).0;
    }

    /// Performs a batch addition and deletion as described on page 11, section 5 in
    /// https://eprint.iacr.org/2020/777.pdf
    pub fn update(
        &self,
        key: &SecretKey,
        additions: &[Element],
        deletions: &[Element],
    ) -> (Self, Vec<Coefficient>) {
        let mut a = *self;
        let c = a.update_assign(key, additions, deletions);
        (a, c)
    }

    /// Performs a batch addition and deletion as described on page 11, section 5 in
    /// https://eprint.iacr.org/2020/777.pdf
    pub fn update_assign(
        &mut self,
        key: &SecretKey,
        additions: &[Element],
        deletions: &[Element],
    ) -> Vec<Coefficient> {
        let mut a = key.batch_additions(additions);
        let d = key.batch_deletions(deletions);

        a.0 *= d.0;
        let coefficients = key
            .create_coefficients(additions, deletions)
            .iter()
            .map(|c| Coefficient(self.0 * c.0))
            .collect();
        self.0 *= a.0;
        coefficients
    }

    /// Convert accumulator to bytes
    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let mut d = [0u8; Self::BYTES];
        d.copy_from_slice(self.0.to_bytes().as_ref());
        d
    }
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use super::*;

    #[test]
    fn new_accmulator_100() {
        let key = SecretKey::new(None);
        let elems = (0..100)
            .map(|_| Element::random())
            .collect::<Vec<Element>>();
        let acc = Accumulator::with_elements(&key, elems.as_slice());
        assert_ne!(acc.0, G1Projective::GENERATOR);
    }

    #[allow(non_snake_case)]
    #[test]
    fn new_accumulator_10K() {
        let key = SecretKey::new(None);
        let elems = (0..10_000)
            .map(|_| Element::random())
            .collect::<Vec<Element>>();
        let acc = Accumulator::with_elements(&key, elems.as_slice());
        assert_ne!(acc.0, G1Projective::GENERATOR);
    }

    #[allow(non_snake_case)]
    #[ignore = "this takes a looooong time"]
    #[test]
    fn new_accumulator_10M() {
        let key = SecretKey::new(None);
        let elems = (0..10_000_000)
            .map(|_| Element::random())
            .collect::<Vec<Element>>();
        let acc = Accumulator::with_elements(&key, elems.as_slice());
        assert_ne!(acc.0, G1Projective::GENERATOR);
    }

    #[test]
    fn add_test() {
        let key = SecretKey::new(None);
        let mut acc = Accumulator(G1Projective::GENERATOR);
        acc.add_assign(&key, Element::hash(b"value1"));
        assert_ne!(acc.0, G1Projective::GENERATOR);
    }

    #[test]
    fn sub_test() {
        let key = SecretKey::new(None);
        let mut acc = Accumulator(G1Projective::GENERATOR);
        assert_eq!(acc.0, G1Projective::GENERATOR);
        acc.add_assign(&key, Element::hash(b"value1"));
        assert_ne!(acc.0, G1Projective::GENERATOR);
        acc.remove_assign(&key, Element::hash(b"value1"));
        assert_eq!(acc.0, G1Projective::GENERATOR);
    }

    #[test]
    fn batch_test() {
        let key = SecretKey::new(None);
        let mut acc = Accumulator(G1Projective::GENERATOR);
        let values = &[Element::hash(b"value1"), Element::hash(b"value2")];
        acc.update_assign(&key, values, &[]);
        assert_ne!(acc.0, G1Projective::GENERATOR);
        acc.update_assign(&key, &[], values);
        assert_eq!(acc.0, G1Projective::GENERATOR);
    }

    #[ignore]
    #[test]
    fn false_witness() {
        let key = SecretKey::new(None);
        let pk = PublicKey::from(&key);
        let elems = (0..100)
            .map(|_| Element::random())
            .collect::<Vec<Element>>();
        let acc = Accumulator::with_elements(&key, &elems);
        let wit = MembershipWitness::new(Element(Scalar::from(101u64)), acc, &key);
        assert!(wit.is_none());
        let wit = MembershipWitness::new(Element(Scalar::ONE), acc, &key);
        assert!(wit.is_some());
        let y = elems[1];
        assert!(wit.unwrap().verify(y, pk, acc));
    }
}
