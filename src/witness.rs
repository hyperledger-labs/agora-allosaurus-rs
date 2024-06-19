use crate::accumulator::{
    generate_fr, pair, schnorr, Accumulator, Element, MembershipWitness, SecretKey, SALT,
};
use crate::utils::{g1, sc};
use blsful::inner_types::*;
use merlin::Transcript;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display, Formatter};

use super::utils::{AccParams, PublicKeys, UserID, SECURITY_BYTES};

/// Data type containing all the witness-related information a user needs
/// (though they still need an accumulator to incorporate into a proof)
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Witness {
    /// The user's secret key
    pub secret_key: SecretKey,
    /// The user's membership witness
    pub witness: MembershipWitness,
    /// The user's BLS signature
    pub signature: G1Projective,
}

impl Witness {
    /// Verifies a witness directly, using the user's ID and their witness (including secret key)
    pub fn verify(
        accumulator: &Accumulator,
        public_keys: &PublicKeys,
        params: &AccParams,
        y: &UserID,
        witness: &Witness,
    ) -> Result<(), &'static str> {
        // Follows the basic pattern of the two pairing checks
        let first_check = multi_miller_loop(&[
            (
                &witness.witness.0.to_affine(),
                &G2Prepared::from((params.get_p2() * y.0 + public_keys.witness_key.0).to_affine()),
            ),
            (
                &accumulator.0.to_affine(),
                &G2Prepared::from(-params.get_p2().to_affine()),
            ),
        ])
        .final_exponentiation()
        .is_identity();
        // let lhs = pair(
        //     witness.witness.0,
        //     params.get_p2() * y.0 + public_keys.witness_key.0,
        // );
        // let rhs = pair(accumulator.0, params.get_p2());
        // if lhs != rhs {
        //     return Err("e()");
        // }

        let second_check = multi_miller_loop(&[
            (
                &witness.signature.to_affine(),
                &G2Prepared::from((params.get_k2() * y.0 + public_keys.sign_key.0).to_affine()),
            ),
            (
                &(params.get_k1() * witness.secret_key.0 + params.get_k0()).to_affine(),
                &G2Prepared::from(-params.get_k2().to_affine()),
            ),
        ])
        .final_exponentiation()
        .is_identity();
        // let lhs = pair(
        //     witness.signature,
        //     params.get_k2() * y.0 + public_keys.sign_key.0,
        // );
        // let rhs = pair(
        //     params.get_k1() * witness.secret_key.0 + params.get_k0(),
        //     params.get_k2(),
        // );
        // if lhs != rhs {
        //     return false;
        // }
        if (first_check & second_check).into() {
            Ok(())
        } else {
            Err("failed")
        }
    }

    /// Constructs a membership proof as a byte string
    /// Most of the work happens in creating mpc
    /// and  mpc.gen_proof
    pub fn make_membership_proof(
        witness: &Witness,
        user_id: &UserID,
        accumulator: &Accumulator,
        params: &AccParams,
        public_keys: &PublicKeys,
        ephemeral_challenge: &[u8; 2 * SECURITY_BYTES],
    ) -> Option<MembershipProof> {
        // Check that witness is valid
        Self::verify(accumulator, public_keys, params, user_id, witness).ok()?;

        // Create commitment
        let mpc = MembershipProofCommitting::new(witness, params, public_keys);

        // Commit to public parameters
        let mut transcript = Transcript::new(b"basic_membership_proof");
        transcript.append_message(
            b"Signature Public Key",
            public_keys.witness_key.to_bytes().as_ref(),
        );
        transcript.append_message(
            b"Witness Public Key",
            public_keys.sign_key.to_bytes().as_ref(),
        );
        transcript.append_message(b"Accumulator", accumulator.to_bytes().as_ref());
        params.add_to_transcript(&mut transcript);
        // Add the elements of the proof to the commitment
        mpc.get_bytes_for_challenge(&mut transcript);
        // Add the challenge
        transcript.append_message(b"Ephemeral challenge", ephemeral_challenge);
        // Create challenge hash
        let challenge = Element::from_transcript(b"challenge", &mut transcript);
        // Construct response and remove unnecessary elements of the commitment
        let proof = mpc.gen_proof(witness, user_id, challenge);

        Some(proof)
    }

    /// Verifies a ZKPoK membership proof given as byte string
    pub fn check_membership_proof(
        proof: &MembershipProof,
        params: &AccParams,
        public_keys: &PublicKeys,
        accumulator: &Accumulator,
        ephemeral_challenge: &[u8; 2 * SECURITY_BYTES],
    ) -> bool {
        // Construct commitments to public parameters/keys
        let mut transcript = Transcript::new(b"basic_membership_proof");
        transcript.append_message(
            b"Signature Public Key",
            public_keys.witness_key.to_bytes().as_ref(),
        );
        transcript.append_message(
            b"Witness Public Key",
            public_keys.sign_key.to_bytes().as_ref(),
        );
        transcript.append_message(b"Accumulator", accumulator.to_bytes().as_ref());
        params.add_to_transcript(&mut transcript);

        // Reconstruct all necessary points and add them to the transcript
        proof.get_bytes_for_challenge(params, public_keys, accumulator, &mut transcript);
        transcript.append_message(b"Ephemeral challenge", ephemeral_challenge);
        // Verifies that the full reconstructed transcript matches the hash
        let challenge = Element::from_transcript(b"challenge", &mut transcript);
        challenge.0 == proof.challenge
    }
}

/// The commit or blinding step for generating a ZKP
/// The next step is to call `get_bytes_for_challenge`
/// to create the fiat shamir heuristic
#[derive(Debug, Copy, Clone)]
struct MembershipProofCommitting {
    pub r: [Scalar; 3],
    pub k: [Scalar; 8],
    pub u_1: G1Projective,
    pub u_2: G1Projective,
    pub r_point: G1Projective,
    pub t_1: G1Projective,
    pub t_2: G1Projective,
    pub pi_1: Gt,
    pub pi_2: Gt,
}

impl MembershipProofCommitting {
    /// Create a new membership proof committing phase
    // Follows the ZKPoK in the PROVE function on page 88
    pub fn new(witness: &Witness, params: &AccParams, public_keys: &PublicKeys) -> Self {
        let rng = rand::rngs::OsRng;
        // Randomly select r_1, r_2, r_3, k_0,..k_7
        let r: [Scalar; 3] = [
            generate_fr(SALT, None, rng),
            generate_fr(SALT, None, rng),
            generate_fr(SALT, None, rng),
        ];
        let k: [Scalar; 8] = [
            generate_fr(SALT, None, rng),
            generate_fr(SALT, None, rng),
            generate_fr(SALT, None, rng),
            generate_fr(SALT, None, rng),
            generate_fr(SALT, None, rng),
            generate_fr(SALT, None, rng),
            generate_fr(SALT, None, rng),
            generate_fr(SALT, None, rng),
        ];

        // U_1 = R_m + r_1Y
        let u_1 = witness.signature + params.get_z1() * r[0];

        // U_2 = C + r_2Y
        let u_2 = witness.witness.0 + params.get_z1() * r[1];

        // R = r_1X + r_2Y + r_3Z
        let r_point = params.get_x1() * r[0] + params.get_y1() * r[1] + params.get_z1() * r[2];

        // T_1 = k_1X + k_2Y + k_3Z
        let t_1 = params.get_x1() * k[1] + params.get_y1() * k[2] + params.get_z1() * k[3];

        // T_1 = k_4X + k_5Y + k_6Z - k_yR
        let t_2 = params.get_x1() * k[4] + params.get_y1() * k[5] + params.get_z1() * k[6]
            - r_point * k[7];

        // Pi_1 = e(K,K)^{k_0} * e(U_1, K)^{-k_7} * e(Z,K)^{k_4} * e(Z,Q_m)^{k_1}
        // To save computation:
        //      = e(k_0K - k_7U_1,K) * e(Z,k_4K + k_1Q_m)
        let pi_1 = pair(params.get_k1() * k[0] - u_1 * k[7], params.get_k2())
            + pair(
                params.get_z1(),
                params.get_k2() * k[4] + public_keys.sign_key.0 * k[1],
            );
        // Pi_2 = e(U_2,P)^{-k_7} * e(Z,P)^{k_5} * e(Z,Q)^{k_2}
        // To save computation:
        //      = e(-k_7U_2 + k_5Z,P) * e(Z,Q)^{k_2}
        let pi_2 = pair(params.get_z1() * k[5] - u_2 * k[7], params.get_p2())
            + pair(params.get_z1(), public_keys.witness_key.0 * k[2]);

        Self {
            r,
            k,
            u_1,
            u_2,
            r_point,
            t_1,
            t_2,
            pi_1,
            pi_2,
        }
    }

    /// Return bytes that need to be hashed for generating challenge.
    ///
    /// U_1 || U_2 || R || T_1 || T_2 || Pi_1 || Pi_2
    pub fn get_bytes_for_challenge(&self, transcript: &mut Transcript) {
        transcript.append_message(b"U_1", &self.u_1.to_compressed());
        transcript.append_message(b"U_2", &self.u_2.to_compressed());
        transcript.append_message(b"R", &self.r_point.to_compressed());
        transcript.append_message(b"T_1", &self.t_1.to_compressed());
        transcript.append_message(b"T_2", &self.t_2.to_compressed());
        transcript.append_message(b"Pi_1", self.pi_1.to_bytes().as_ref());
        transcript.append_message(b"Pi_2", self.pi_2.to_bytes().as_ref());
    }

    /// Given the challenge value, compute the s values for Fiat-Shamir and return the actual
    /// proof to be sent to the verifier
    // Follows the second part of the PROVE function on page 88
    pub fn gen_proof(
        &self,
        witness: &Witness,
        user_id: &UserID,
        challenge_hash: Element,
    ) -> MembershipProof {
        let challenge_hash = challenge_hash.0;

        let s0 = schnorr(self.k[0], witness.secret_key.0, challenge_hash);
        let s1 = schnorr(self.k[1], self.r[0], challenge_hash);
        let s2 = schnorr(self.k[2], self.r[1], challenge_hash);
        let s3 = schnorr(self.k[3], self.r[2], challenge_hash);
        let s4 = schnorr(self.k[4], self.r[0] * user_id.0, challenge_hash);
        let s5 = schnorr(self.k[5], self.r[1] * user_id.0, challenge_hash);
        let s6 = schnorr(self.k[6], self.r[2] * user_id.0, challenge_hash);
        let s7 = schnorr(self.k[7], user_id.0, challenge_hash);

        MembershipProof {
            u_1: self.u_1,
            u_2: self.u_2,
            r: self.r_point,
            challenge: challenge_hash,
            s_0: s0,
            s_1: s1,
            s_2: s2,
            s_3: s3,
            s_4: s4,
            s_5: s5,
            s_6: s6,
            s_7: s7,
        }
    }
}

/// A ZKP membership proof
// Primary job of this struct is to construct a byte string
// from the arguments
// Also contains the function from VER on page 89
// to use a proof to reconstruct missing parts of it
#[derive(Debug, Default, Copy, Clone, Deserialize, Serialize)]
pub struct MembershipProof {
    pub(crate) u_1: G1Projective,
    pub(crate) u_2: G1Projective,
    pub(crate) r: G1Projective,
    pub(crate) challenge: Scalar,
    pub(crate) s_0: Scalar,
    pub(crate) s_1: Scalar,
    pub(crate) s_2: Scalar,
    pub(crate) s_3: Scalar,
    pub(crate) s_4: Scalar,
    pub(crate) s_5: Scalar,
    pub(crate) s_6: Scalar,
    pub(crate) s_7: Scalar,
}

impl Display for MembershipProof {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MembershipProof {{ u_1: {}, u_2: {}, r: {}, challenge {}, s_0: {}
             s_1: {}, s_2: {},  s_3: {},  s_4: {},  s_5: {},  s_6: {},  s_7: {} }}",
            self.u_1,
            self.u_2,
            self.r,
            self.challenge,
            self.s_0,
            self.s_1,
            self.s_2,
            self.s_3,
            self.s_4,
            self.s_5,
            self.s_6,
            self.s_7
        )
    }
}

impl MembershipProof {
    /// The size of the proof in bytes
    pub const BYTES: usize = 432;

    /// Get the byte representation of the proof
    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let mut res = [0u8; Self::BYTES];
        res[0..48].copy_from_slice(&self.u_1.to_compressed());
        res[48..96].copy_from_slice(&self.u_2.to_compressed());
        res[96..144].copy_from_slice(&self.r.to_compressed());
        res[144..176].copy_from_slice(&self.challenge.to_be_bytes());
        res[176..208].copy_from_slice(&self.s_0.to_be_bytes());
        res[208..240].copy_from_slice(&self.s_1.to_be_bytes());
        res[240..272].copy_from_slice(&self.s_2.to_be_bytes());
        res[272..304].copy_from_slice(&self.s_3.to_be_bytes());
        res[304..336].copy_from_slice(&self.s_4.to_be_bytes());
        res[336..368].copy_from_slice(&self.s_5.to_be_bytes());
        res[368..400].copy_from_slice(&self.s_6.to_be_bytes());
        res[400..432].copy_from_slice(&self.s_7.to_be_bytes());
        res
    }

    /// Convert a byte representation to a proof
    pub fn from_bytes(input: &[u8; Self::BYTES]) -> Result<Self, &'static str> {
        Ok(Self {
            u_1: g1(&input[0..48])?,
            u_2: g1(&input[48..96])?,
            r: g1(&input[96..144])?,
            challenge: sc(&input[144..176])?,
            s_0: sc(&input[176..208])?,
            s_1: sc(&input[208..240])?,
            s_2: sc(&input[240..272])?,
            s_3: sc(&input[272..304])?,
            s_4: sc(&input[304..336])?,
            s_5: sc(&input[336..368])?,
            s_6: sc(&input[368..400])?,
            s_7: sc(&input[400..432])?,
        })
    }

    /// Reconstructs t_1, t_2, pi_1, pi_2
    /// from the rest of the proof
    /// Then adds these (and other proof points)
    /// to the transcript
    pub fn get_bytes_for_challenge(
        &self,
        params: &AccParams,
        public_keys: &PublicKeys,
        accumulator: &Accumulator,
        transcript: &mut Transcript,
    ) {
        let t_1 =
            params.get_x1() * self.s_1 + params.get_y1() * self.s_2 + params.get_z1() * self.s_3
                - self.r * self.challenge;
        let t_2 =
            params.get_x1() * self.s_4 + params.get_y1() * self.s_5 + params.get_z1() * self.s_6
                - self.r * self.s_7;
        let pi_1 = pair(
            params.get_k1() * self.s_0 - self.u_1 * self.s_7
                + params.get_z1() * self.s_4
                + params.get_k0() * self.challenge,
            params.get_k2(),
        ) + pair(
            params.get_z1() * self.s_1 - self.u_1 * self.challenge,
            public_keys.sign_key.0,
        );
        let pi_2 = pair(
            -self.u_2 * self.s_7 + params.get_z1() * self.s_5 + accumulator.0 * self.challenge,
            params.get_p2(),
        ) + pair(
            params.get_z1() * self.s_2 - self.u_2 * self.challenge,
            public_keys.witness_key.0,
        );
        transcript.append_message(b"U_1", self.u_1.to_bytes().as_ref());
        transcript.append_message(b"U_2", self.u_2.to_bytes().as_ref());
        transcript.append_message(b"R", self.r.to_bytes().as_ref());
        transcript.append_message(b"T_1", t_1.to_bytes().as_ref());
        transcript.append_message(b"T_2", t_2.to_bytes().as_ref());
        transcript.append_message(b"Pi_1", pi_1.to_bytes().as_ref());
        transcript.append_message(b"Pi_2", pi_2.to_bytes().as_ref());
    }
}
