// SPDX-License-Identifier: LGPL-3.0-or-later

//! BIP-32 hierarchical-deterministic key derivation as [zkboo] circuits.

#![no_std]
extern crate alloc;

mod address;
mod child;
mod master;
mod pubkey;
mod seed;
mod util;

pub use address::{ethereum_address, ethereum_address_with_tables};
pub use child::{
    HARDENED_OFFSET, hardened_child_key, normal_child_key, normal_child_key_with_tables,
};
pub use master::{MASTER_KEY_HMAC_KEY, master_key};
pub use pubkey::{public_key, public_key_with_tables};
pub use seed::{PBKDF2_ROUNDS, SALT_PREFIX, bip39_seed, bip39_seed_partial};
pub use util::{be_bytes_to_word, word_to_be_bytes};
