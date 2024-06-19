//! The `accumulator` module provides the necessary tools to create and update an accumulator.
//! according to VB paper https://eprint.iacr.org/2020/777.pdf
mod acc;
mod key;
mod proof;
mod proof_message;
mod utils;
mod witness;

pub use acc::*;
pub use key::*;
pub use proof::*;
pub use proof_message::*;
pub use utils::*;
pub use witness::*;
