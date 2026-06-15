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
///
/// Computes `I = HMAC-SHA512("Bitcoin seed", seed)` and splits it into the master private key
/// `IL = I[0..32]` and the master chain code `IR = I[32..64]`, each returned as 32 big-endian
/// bytes.
///
/// The caller is responsible for allocating `seed` (typically as secret witness inputs via
/// [Frontend::input](zkboo::backend::Frontend::input)); the `"Bitcoin seed"` key is allocated
/// internally as a public constant.
///
/// Note: BIP-32 requires `0 < IL < n` (the secp256k1 group order) for the seed to be valid; this
/// holds with overwhelming probability and is not enforced here. `IL` is returned as the raw
/// 32-byte big-endian integer, *not* reduced modulo `n`.
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
