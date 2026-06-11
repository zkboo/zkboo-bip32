// SPDX-License-Identifier: LGPL-3.0-or-later

//! BIP-32 hierarchical-deterministic key derivation as [zkboo] circuits.
//!
//! These building blocks implement the *proof of seed* idea: a wallet proves knowledge of the
//! seed (or an intermediate key) from which an account was derived, via a quantum-resistant
//! zero-knowledge proof of the BIP-32 / BIP-39 derivation, without revealing the secret.
//!
//! See <https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki>.

#![no_std]
extern crate alloc;

mod address;
mod child;
mod master;
mod pubkey;
mod seed;
mod util;

pub use address::ethereum_address;
pub use child::{HARDENED_OFFSET, hardened_child_key, normal_child_key};
pub use master::{MASTER_KEY_HMAC_KEY, master_key};
pub use pubkey::public_key;
pub use seed::{PBKDF2_ROUNDS, SALT_PREFIX, bip39_seed, bip39_seed_partial};
pub use util::{be_bytes_to_word, word_to_be_bytes};
