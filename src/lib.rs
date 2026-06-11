// SPDX-License-Identifier: LGPL-3.0-or-later

//! BIP-32 hierarchical-deterministic key derivation as [zkboo] circuits.

#![no_std]
extern crate alloc;

mod child;
mod master;
mod seed;

pub use child::{HARDENED_OFFSET, hardened_child_key};
pub use master::{MASTER_KEY_HMAC_KEY, master_key};
pub use seed::{PBKDF2_ROUNDS, SALT_PREFIX, bip39_seed};
