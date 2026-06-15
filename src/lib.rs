// SPDX-License-Identifier: LGPL-3.0-or-later

//! BIP-32 hierarchical-deterministic key derivation as [zkboo] circuits.

#![no_std]
extern crate alloc;

mod master;

pub use master::{MASTER_KEY_HMAC_KEY, master_key};
