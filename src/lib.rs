/*
    Copyright Hyperledger Foundation. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! An implementation of ALLOSAUR see <https://eprint.iacr.org/2022/1362>
#![deny(
    missing_docs,
    unused_import_braces,
    unused_qualifications,
    unused_parens,
    unused_lifetimes,
    unconditional_recursion,
    unused_extern_crates,
    trivial_casts,
    trivial_numeric_casts
)]
mod servers;
mod user;
mod utils;
mod witness;

#[cfg(test)]
mod tests;

pub mod accumulator;
pub use servers::*;
pub use user::*;
pub use witness::*;
