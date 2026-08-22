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
mod bitcoin;
mod child;
mod ed25519;
mod master;
mod pubkey;
mod seed;
mod util;

pub use address::{ethereum_address, ethereum_address_with_tables};
pub use bitcoin::{
    TAP_TWEAK_TAG_HASH, compressed_pubkey, hash160, p2sh_p2wpkh_payload,
    p2sh_p2wpkh_payload_with_tables, pubkey_hash160, pubkey_hash160_with_tables, tagged_hash,
    taproot_output_key, taproot_output_key_with_tables,
};
pub use child::{
    HARDENED_OFFSET, hardened_child_key, normal_child_key, normal_child_key_with_tables,
};
pub use ed25519::{
    SLIP10_ED25519_HMAC_KEY, SOLANA_COIN_TYPE, ed25519_public_key, ed25519_public_key_with_tables,
    slip10_ed25519_child, slip10_ed25519_master, solana_pubkey, solana_pubkey_with_tables,
};
pub use master::{MASTER_KEY_HMAC_KEY, master_key};
pub use pubkey::{public_key, public_key_with_tables};
pub use seed::{
    PBKDF2_ROUNDS, SALT_PREFIX, bip39_seed, bip39_seed_partial, bip39_seed_with_salt_words,
};
pub use util::{be_bytes_to_word, word_to_be_bytes};
