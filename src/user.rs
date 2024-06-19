use crate::accumulator::{Accumulator, Element, MembershipWitness, SecretKey};
use blsful::inner_types::*;
use merlin::Transcript;
use serde::{Deserialize, Serialize};

use super::{servers::Server, utils::*, witness::*};

/// The data a user needs to track
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct User {
    /// ID value y
    pub id: UserID,
    /// Wrapper type for (x, C, R_m)
    pub witness: Option<Witness>,
    /// Latest accumulator for the witness
    pub accumulator: Accumulator,
    /// The accumulator's public keys
    pub public_keys: PublicKeys,
    /// the epoch when the witness was last known to be valid
    pub epoch: usize,
}

impl User {
    /// New "empty" user
    pub fn new(server: &Server, id: UserID) -> User {
        User {
            id,
            witness: None,
            accumulator: server.get_accumulator(),
            public_keys: server.get_public_keys(),
            epoch: server.get_epoch(),
        }
    }

    /// Generates a random user and uses the secret keys provided
    /// to create a witness for the new random user
    pub fn random(
        alpha: &SecretKey,
        s: &SecretKey,
        acc_params: AccParams,
        accumulator: Accumulator,
        public_keys: PublicKeys,
        epoch: usize,
    ) -> Self {
        let id = UserID::random();
        let long_term_secret = Element::random().0;
        let signature = ((acc_params.get_k1() * long_term_secret) + acc_params.get_k0())
            * (s.0 + id.0).invert().unwrap();

        // 1. {A1, \pi, id} = lts * K1, b <- RO, B1 = b * K1, c = H(K1, A1, B1), lts' = b + c.lts, \pi = {c, lts'}
        // 2. Verify \pi
        // 3. A2 = ( K0 + A1 ) * (1/{s+id})
        // 4. A3 = V * (1/{alpha+id})

        Self {
            id,
            witness: Some(Witness {
                signature,
                witness: MembershipWitness::new(id, accumulator, alpha).unwrap(),
                secret_key: SecretKey(long_term_secret),
            }),
            accumulator,
            public_keys,
            epoch,
        }
    }

    /// Get the accumulator for this user
    pub fn get_accumulator(&self) -> Accumulator {
        self.accumulator
    }

    /// Get the ID for this user
    pub fn get_id(&self) -> UserID {
        self.id
    }

    /// Creates a new witness for the user
    /// by generating a random new secret key,
    /// create a ZKPoK of this key, and ask the server given
    /// as an argument for a new witness and long-term signature
    pub fn create_witness(&mut self, params: &AccParams, server: &Server) {
        let key = SecretKey::new(None);
        let user_pub_key = params.get_k1() * key.0;
        // Create a Schnorr proof
        let k = Element::random();
        let k_point = params.get_k1() * k.0;
        let mut transcript = Transcript::new(b"user_signature_proof");
        transcript.append_message(b"user_pub_key", user_pub_key.to_bytes().as_ref());
        transcript.append_message(b"commitment", k_point.to_bytes().as_ref());
        let challenge = Element::from_transcript(b"challenge", &mut transcript);
        let response = k.0 - challenge.0 * key.0;
        // Send Schnorr proof and ID to server
        if let Some((witness, signature)) = server.witness(
            params,
            &self.id,
            &challenge,
            &Element(response),
            &user_pub_key,
        ) {
            self.witness = Some(Witness {
                secret_key: key,
                witness,
                signature,
            });
            self.epoch = server.get_epoch();
            self.accumulator = server.get_accumulator();
        }
    }

    /// Prepares the secret shares that will be sent to each server
    /// during the ALLOSAUR update
    pub fn prepare_for_update(
        &self,
        new_epoch: usize,
        num_servers: usize,
        threshold: usize,
    ) -> Result<UserUpdate, &'static str> {
        if num_servers < threshold {
            return Err("invalid threshold");
        }
        if threshold <= 1 {
            return Err("invalid threshold");
        }

        let d = new_epoch - self.epoch;
        let mut k = ((d as f64) * 2.5).sqrt() as usize;

        // We expect 32*(k-1) bytes user->server
        // and 80*ceil(d/k) bytes server->user
        // We want these to balance, with preference for user->server since it saves
        // the user elliptic curve computations
        while 2 * k < 5 * (d + k - 1) / k {
            k += 1;
        }

        // Create y, y^2, ..,. y^k-1
        let mut y_power = self.id.0;
        // y_shares maps from the input value of a Shamir share into a vector
        // of shares for each power of y
        let mut y_values = Vec::with_capacity(num_servers);
        let mut y_shares = Vec::with_capacity(2 * num_servers * k);
        // Create all keys in the hashmap from splitting the first power of y
        for (value, share) in shamir_share(threshold, num_servers, y_power) {
            y_shares.push(vec![share]);
            y_values.push(value);
        }
        // Add to all vectors in the hash map
        for _ in 1..k - 1 {
            y_power *= self.id.0; // = y^{i+1}
            for (i, (_, share)) in shamir_share(threshold, num_servers, y_power)
                .iter()
                .enumerate()
            {
                y_shares[i].push(*share);
            }
        }

        Ok(UserUpdate {
            epoch_diff: d,
            y_shares,
            y_values,
        })
    }

    /// Finalizes an update based on the response shares from an array of servers
    /// and the shares from the pre-computation. Given an old witness as input,
    /// this updates that witness.
    pub fn post_update(
        &self,
        old_witness: MembershipWitness,
        threshold: usize,
        y_shares: &[Vec<Scalar>],
        y_values: &[Scalar],
        dvs: &[(Vec<Scalar>, Vec<G1Projective>)],
    ) -> Result<MembershipWitness, &'static str> {
        // d_chunks_shares is a vector of "chunks" of the polynomial d
        // such that d(x) = d[0] + d[1]*y^1 + d[2]*y^2 + ....
        // Since these chunks are returned as secret shares from the servers,
        // in this data structure it is Vec<(Scalar, Scalar)>, i.e., a set
        // of Shamir shares
        let mut d_chunks_shares: Vec<Vec<(Scalar, Scalar)>> = Vec::new();
        // v_chunks_shares is the same, for the polynomial v(y,alpha)
        let mut v_chunks_shares: Vec<Vec<(Scalar, G1Projective)>> = Vec::new();
        // We only need a threshold of these, but this is fine for now
        for (i, _power_shares) in y_shares.iter().enumerate() {
            // d = vector of d polynomial chunks
            // w = vector of w polynomial chunks
            if d_chunks_shares.is_empty() {
                d_chunks_shares = vec![Vec::new(); dvs[i].0.len()];
            };
            for (ii, d) in dvs[i].0.iter().enumerate() {
                d_chunks_shares[ii].push((y_values[i], *d));
            }
            if v_chunks_shares.is_empty() {
                v_chunks_shares = vec![Vec::new(); dvs[i].1.len()];
            };
            for (ii, v) in dvs[i].1.iter().enumerate() {
                v_chunks_shares[ii].push((y_values[i], *v));
            }
        }

        // We save on Shamir share reconstruction because we reconstruct all the secrets with the
        // same coefficients
        let (coefficients, check_coefficients) =
            shamir_coefficients(threshold, &d_chunks_shares[0]);
        // Iterates through all the shares of all the chunks, reconstructs the chunk from the shares,
        // then adds this to the polynomials d and v
        // Since v_chunks_shares and d_chunks_shares have the same length, we iterate simultaneously
        let mut new_witness = old_witness;
        let mut d_test = Scalar::ONE;
        for (i, shares_of_d_chunk) in d_chunks_shares.iter().enumerate() {
            // Through all shares, just rebuild
            match shamir_rebuild_scalar(shares_of_d_chunk, &coefficients, &check_coefficients) {
                Some(d_chunk) => {
                    if d_chunk.is_zero().into() {
                        return Err("user has been deleted");
                    } // user was deleted!
                    d_test *= d_chunk;
                    match shamir_rebuild_point(
                        &v_chunks_shares[i],
                        &coefficients,
                        &check_coefficients,
                    ) {
                        Some(v_chunk) => {
                            // Note that d and v are not just chunks of an update of size k
                            new_witness = MembershipWitness(
                                (new_witness.0 - v_chunk) * d_chunk.invert().unwrap(),
                            );
                        }
                        None => {
                            return Err("malicious server");
                        } // update failed!
                    }
                }
                None => {
                    return Err("malicious server");
                } // update failed!
                  // Failed update implies a malfunctioning/malicious server
                  // The real protocol should start posting blame messages
            }
        }
        Ok(new_witness)
    }

    /// Updates to the latest available epoch, from a set of servers
    pub fn update(&mut self, servers: &[Server], threshold: usize) -> Result<(), &'static str> {
        if self.witness.is_none() {
            return Err("No witness");
        }
        // // Check that current witness is valid
        // let acc = server.get_accumulator();
        // if !ver(self.accumulator, self.wit_public_key, self.sign_public_key, params, self.id, self.witness){
        //     return;
        // }
        // If so, attempt update

        // Precompute shares
        let (d, y_shares, y_values) =
            match self.prepare_for_update(servers[0].get_epoch(), servers.len(), threshold) {
                Ok(UserUpdate {
                    epoch_diff,
                    y_shares,
                    y_values,
                }) => (epoch_diff, y_shares, y_values),
                Err(e) => return Err(e),
            };
        // Get answer from each server (directly)
        let dvs: Vec<(Vec<Scalar>, Vec<G1Projective>)> = (0..servers.len())
            .map(|i| servers[i].update(d, &y_shares[i]))
            .collect();

        // Post-processes the update and returns the witness
        match self.post_update(
            self.witness.as_ref().expect("to have a witness").witness,
            threshold,
            &y_shares,
            &y_values,
            &dvs,
        ) {
            Ok(new_witness) => {
                if let Some(witness) = self.witness.as_mut() {
                    witness.witness = new_witness;
                }

                self.accumulator = servers[0].get_accumulator();
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Constructs a membership proof as a byte string
    pub fn make_membership_proof(
        &self,
        params: &AccParams,
        public_keys: &PublicKeys,
        ephemeral_challenge: &[u8; 2 * SECURITY_BYTES],
    ) -> Option<MembershipProof> {
        // If the user has an invalid witness, just send all 0s
        match &self.witness {
            None => None,
            Some(witness) => Witness::make_membership_proof(
                witness,
                &self.id,
                &self.accumulator,
                params,
                public_keys,
                ephemeral_challenge,
            ),
        }
    }

    /// Checks whether the user has a valid witness for the given accumulator
    /// Compares to the user's internal copy of the signature key
    pub fn check_witness(
        &self,
        params: &AccParams,
        accumulator: &Accumulator,
    ) -> Result<(), &'static str> {
        match &self.witness {
            Some(witness) => {
                Witness::verify(accumulator, &self.public_keys, params, &self.id, witness)
            }
            None => Err("no witness"),
        }
    }
}

/// A user update message
#[derive(Clone, Debug)]
pub struct UserUpdate {
    /// The difference in epochs between the user's witness and the servers
    pub epoch_diff: usize,
    /// The secret shares for the user's ID to send to the server
    pub y_shares: Vec<Vec<Scalar>>,
    /// The powers of the user's ID to be retained
    pub y_values: Vec<Scalar>,
}
