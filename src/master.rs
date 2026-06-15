// SPDX-License-Identifier: LGPL-3.0-or-later

//! BIP-32 master key derivation from a seed.

use alloc::vec::Vec;
use zkboo::backend::{Allocator, Backend, WordRef};
use zkboo_hmac::hmac;
use zkboo_sha2::{SHA512_BLOCKSIZE, sha512bytes};

/// The fixed HMAC key used to derive the BIP-32 master key from a seed: the ASCII bytes of
/// `"Bitcoin seed"`, as specified by BIP-32.
pub const MASTER_KEY_HMAC_KEY: &[u8] = b"Bitcoin seed";

/// Derives the BIP-32 master extended key from a binary `seed`.
pub fn master_key<B: Backend>(
    allocator: Allocator<B>,
    seed: Vec<WordRef<B, u8>>,
) -> ([WordRef<B, u8>; 32], [WordRef<B, u8>; 32]) {
    let key = MASTER_KEY_HMAC_KEY
        .iter()
        .map(|&b| allocator.alloc(b))
        .collect::<Vec<_>>();
    let i = hmac(allocator, key, seed, sha512bytes, SHA512_BLOCKSIZE);
    let mut words = i.into_iter();
    let il = core::array::from_fn(|_| words.next().unwrap());
    let ir = core::array::from_fn(|_| words.next().unwrap());
    return (il, ir);
}
