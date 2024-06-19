// Runs a suite of tests on the basic ALLOSAUR functionality

use crate::accumulator::{Accumulator, Element, MembershipWitness, PublicKey, SecretKey};
use crate::{*, utils::*};
use blsful::inner_types::*;
use rand::RngCore;

// Generates a new accumulator and adds elements
#[test]
fn new_accmulator_100() {
    let params = AccParams::default();
    let mut server = Server::new(&params);
    for _ in 0..100 {
        server.add(UserID::random());
    }
}

// Tests that Shamir sharing can rebuild secrets
#[test]
fn test_shamir() {
    let threshold = 3;
    let num_shares = 5;
    let secret = Element::random().0;
    let shares = shamir_share(threshold, num_shares, secret);
    let coeffs = shamir_coefficients(threshold, &shares);
    let rebuild = shamir_rebuild_scalar(&shares, &coeffs.0, &None);
    assert_eq!(secret, rebuild.unwrap());
}

// Tests that Shamir sharing can rebuild secrets
// and pass an internal validity check
#[test]
fn test_shamir_check() {
    let threshold = 3;
    let num_shares = 5;
    let secret = Scalar::random(rand::rngs::OsRng);
    let shares = shamir_share(threshold, num_shares, secret);
    let coeffs = shamir_coefficients(threshold, &shares);
    let rebuild = shamir_rebuild_scalar(&shares, &coeffs.0, &coeffs.1);
    assert_eq!(secret, rebuild.unwrap());
}

// Test that basic affine transformations on Shamir shares
// are homomorphic
#[test]
fn test_shamir_affine() {
    let threshold = 3;
    let num_shares = 5;
    let secret = Scalar::random(rand::rngs::OsRng);
    let a = Scalar::random(rand::rngs::OsRng);
    let b = Scalar::random(rand::rngs::OsRng);
    let mut shares = shamir_share(threshold, num_shares, secret);
    for share in shares.iter_mut() {
        share.1 = share.1 * a + b;
    }
    let coeffs = shamir_coefficients(threshold, &shares);
    let rebuild = shamir_rebuild_scalar(&shares, &coeffs.0, &coeffs.1);
    assert_eq!(a * secret + b, rebuild.unwrap());
}

// Test that Shamir shares as affine transformations with elliptic curve
// points works
#[test]
fn test_shamir_point() {
    let threshold = 3;
    let num_shares = 5;
    let secret_1 = Scalar::random(rand::rngs::OsRng);
    let secret_2 = Scalar::random(rand::rngs::OsRng);
    let a = G1Projective::generator();
    let b = G1Projective::generator() * SecretKey::new(None).0;
    let shares_1 = shamir_share(threshold, num_shares, secret_1);
    let shares_2 = shamir_share(threshold, num_shares, secret_2);
    let mut point_shares = Vec::new();
    for i in 0..shares_1.len() {
        point_shares.push((shares_1[i].0, a * shares_1[i].1 + b * shares_2[i].1));
    }
    let coeffs = shamir_coefficients(threshold, &shares_1);
    let rebuild = shamir_rebuild_point(&point_shares, &coeffs.0, &coeffs.1);
    assert_eq!(a * secret_1 + b * secret_2, rebuild.unwrap());
}

// Issue each user a witness and check that it works
#[test]
fn test_witness_issue() {
    let params = AccParams::default();
    let mut server = Server::new(&params);
    let mut users = Vec::new();
    for _ in 0..10 {
        users.push(User::new(&server, UserID::random()));
        server.add(users.last().unwrap().get_id());
        users.last_mut().unwrap().create_witness(&params, &server);
        assert!(users
            .last()
            .unwrap()
            .check_witness(&params, &server.get_accumulator())
            .is_ok());
    }
}

// Tests that a user can update successfully after some deletions
#[test]
fn test_witness_update() {
    const SERVERS: usize = 5;
    const SERVER_THRESHOLD: usize = 3;
    const USERS: usize = 10;
    let params = AccParams::default();
    let mut server = Server::new(&params);
    let mut users = Vec::new();
    for _ in 0..USERS {
        users.push(User::new(&server, UserID::random()));
        server.add(users.last().unwrap().get_id());
        users.last_mut().unwrap().create_witness(&params, &server);
        assert!(users
            .last()
            .unwrap()
            .check_witness(&params, &server.get_accumulator())
            .is_ok());
    }
    for i in 1..USERS {
        server.delete(users[i].get_id());
        assert!(!users[i]
            .check_witness(&params, &server.get_accumulator())
            .is_ok());
    }
    let servers: Vec<Server> = (0..SERVERS).map(|_| server.clone()).collect();
    let res = users[0].update(&servers, SERVER_THRESHOLD);
    assert!(res.is_ok());
    assert!(users[0]
        .check_witness(&params, &server.get_accumulator())
        .is_ok());
}

// Tests that a user can update successfully after some deletions and additions
#[test]
fn test_witness_update_add() {
    const SERVERS: usize = 5;
    const SERVER_THRESHOLD: usize = 3;
    const USERS: usize = 10;
    let params = AccParams::default();
    let mut server = Server::new(&params);
    let mut users = Vec::new();
    for _ in 0..USERS {
        users.push(User::new(&server, UserID::random()));
        server.add(users.last().unwrap().get_id());
        users.last_mut().unwrap().create_witness(&params, &server);
        assert!(users
            .last()
            .unwrap()
            .check_witness(&params, &server.get_accumulator())
            .is_ok());
    }
    for i in 1..USERS {
        server.delete(users[i].get_id());
        assert!(!users[i]
            .check_witness(&params, &server.get_accumulator())
            .is_ok());
    }
    for i in 1..USERS {
        server.delete(users[i].get_id());
        users.push(User::new(&server, UserID::random()));
        server.add(users.last().unwrap().get_id());
    }
    let servers: Vec<Server> = (0..SERVERS).map(|_| server.clone()).collect();
    let res = users[0].update(&servers, SERVER_THRESHOLD);
    assert!(res.is_ok());
    assert!(users[0]
        .check_witness(&params, &server.get_accumulator())
        .is_ok());
}

// Tests membership proofs
#[test]
fn basic_membership_proof() {
    let params = AccParams::default();
    let mut server = Server::new(&params);
    let mut users = Vec::new();
    for _ in 0..10 {
        users.push(User::new(&server, UserID::random()));
        server.add(users.last().unwrap().get_id());
        users.last_mut().unwrap().create_witness(&params, &server);
    }
    for i in 0..10 {
        let mut ephemeral_challenge = [0u8; 2 * SECURITY_BYTES];
        rand::rngs::OsRng.fill_bytes(&mut ephemeral_challenge);
        let proof = users[i]
            .make_membership_proof(&params, &server.get_public_keys(), &ephemeral_challenge)
            .unwrap();

        assert!(Witness::check_membership_proof(
            &proof,
            &params,
            &server.get_public_keys(),
            &server.get_accumulator(),
            &ephemeral_challenge
        ));
    }
}

// Tests that membership proof fails when users are deleted
#[test]
fn basic_membership_proof_failure() {
    const SERVERS: usize = 10;

    let params = AccParams::default();
    let mut server = Server::new(&params);
    let mut users = Vec::new();
    for _ in 0..SERVERS {
        users.push(User::new(&server, UserID::random()));
        server.add(users.last().unwrap().get_id());
        users.last_mut().unwrap().create_witness(&params, &server);
    }
    for i in 1..SERVERS {
        server.delete(users[i].get_id());
    }
    for i in 0..SERVERS {
        let mut ephemeral_challenge = [0u8; 2 * SECURITY_BYTES];
        rand::rngs::OsRng.fill_bytes(&mut ephemeral_challenge);
        let proof = users[i]
            .make_membership_proof(&params, &server.get_public_keys(), &ephemeral_challenge)
            .unwrap();

        assert!(!Witness::check_membership_proof(
            &proof,
            &params,
            &server.get_public_keys(),
            &server.get_accumulator(),
            &ephemeral_challenge
        ));
    }
}

// Tests that the split update works correctly
#[test]
fn test_split_witness_update() {
    const SERVERS: usize = 5;
    const SERVER_THRESHOLD: usize = 3;
    const USERS: usize = 10;
    let params = AccParams::default();
    let mut server = Server::new(&params);
    let mut users = Vec::new();
    for _ in 0..USERS {
        users.push(User::new(&server, UserID::random()));
        server.add(users.last().unwrap().get_id());
        users.last_mut().unwrap().create_witness(&params, &server);
        assert!(users
            .last()
            .unwrap()
            .check_witness(&params, &server.get_accumulator())
            .is_ok());
    }
    for i in 1..USERS {
        server.delete(users[i].get_id());
        assert!(!users[i]
            .check_witness(&params, &server.get_accumulator())
            .is_ok());
    }
    let servers: Vec<Server> = (0..SERVERS).map(|_| server.clone()).collect();
    let res = users[0].prepare_for_update(servers[0].get_epoch(), SERVERS, SERVER_THRESHOLD);
    assert!(res.is_ok());
    let UserUpdate {
        epoch_diff: d,
        y_shares,
        y_values,
    } = res.unwrap();
    let dvs: Vec<(Vec<Scalar>, Vec<G1Projective>)> = (0..SERVERS)
        .map(|i| servers[i].update(d, &y_shares[i]))
        .collect();
    let res = users[0].post_update(
        users[0].witness.as_ref().unwrap().witness,
        SERVER_THRESHOLD,
        &y_shares,
        &y_values,
        &dvs,
    );
    assert!(res.is_ok());
    users[0].witness.as_mut().map(|w| w.witness = res.unwrap());
    assert!(users[0]
        .check_witness(&params, &server.get_accumulator())
        .is_ok());
}

// Tests that a user can update successfully after some deletions and additions
// With the split update
#[test]
fn test_witness_split_update_add() {
    const SERVERS: usize = 5;
    const SERVER_THRESHOLD: usize = 3;
    const USERS: usize = 10;
    let params = AccParams::default();
    let mut server = Server::new(&params);
    let mut users = Vec::new();
    for _ in 0..USERS {
        users.push(User::new(&server, UserID::random()));
        server.add(users.last().unwrap().get_id());
        users.last_mut().unwrap().create_witness(&params, &server);
        assert!(users
            .last()
            .unwrap()
            .check_witness(&params, &server.get_accumulator())
            .is_ok());
    }
    for i in 1..USERS {
        server.delete(users[i].get_id());
        assert!(!users[i]
            .check_witness(&params, &server.get_accumulator())
            .is_ok());
    }
    for i in 1..USERS {
        server.delete(users[i].get_id());
        users.push(User::new(&server, UserID::random()));
        server.add(users.last().unwrap().get_id());
    }
    let servers: Vec<Server> = (0..SERVERS).map(|_| server.clone()).collect();
    let res = users[0].prepare_for_update(servers[0].get_epoch(), SERVERS, SERVER_THRESHOLD);
    assert!(res.is_ok());
    let UserUpdate {
        epoch_diff: d,
        y_shares,
        y_values,
    } = res.unwrap();
    let dvs: Vec<(Vec<Scalar>, Vec<G1Projective>)> = (0..SERVERS)
        .map(|i| servers[i].update(d, &y_shares[i]))
        .collect();

    let res = users[0].post_update(
        users[0].witness.as_ref().unwrap().witness,
        SERVER_THRESHOLD,
        &y_shares,
        &y_values,
        &dvs,
    );
    assert!(res.is_ok());
    users[0].witness.as_mut().map(|w| w.witness = res.unwrap());
    assert!(users[0]
        .check_witness(&params, &server.get_accumulator())
        .is_ok());
}

// Tests that our single-server protocol works as expected
// Including also splitting additions
// Identical logic to the single-server benchmark
#[test]
fn single_server_split_batch_update() {
    const USERS: usize = 1500;
    const ADDITIONS: usize = 200;
    const DELETIONS: usize = 200;
    const SLICES: usize = 50;
    let key = SecretKey::new(None);
    let pk = PublicKey::from(&key);
    let items: Vec<Element> = (0..USERS).map(|_| Element::random()).collect();
    let mut acc = Accumulator::with_elements(&key, items.as_slice());

    let y = items.last().unwrap().clone();
    let mut witness = MembershipWitness::new(y, acc, &key).unwrap();

    let additions: Vec<Element> = (0..ADDITIONS).map(|_| Element::random()).collect();
    let (deletions, _) = items.split_at(DELETIONS);
    let mut split_additions: Vec<&[Element]> = additions.chunks(SLICES).collect();

    let deletions = deletions.to_vec();
    let mut split_deletions: Vec<&[Element]> = deletions.chunks(SLICES).collect();
    if split_deletions.len() < split_additions.len() {
        split_deletions.resize(split_additions.len(), &[]);
    }
    if split_additions.len() < split_deletions.len() {
        split_additions.resize(split_deletions.len(), &[]);
    }

    let mut deltas = vec![Vec::new(); split_additions.len() + split_deletions.len()];
    for (i, addition) in split_additions.iter().enumerate() {
        deltas[i] = acc.update_assign(&key, addition, split_deletions[i]);
    }
    for (i, addition) in split_additions.iter().enumerate() {
        witness.batch_update_assign(y, &addition, &split_deletions[i], &deltas[i]);
    }
    assert!(witness.verify(y, pk, acc));
}
