// SPDX-License-Identifier: LGPL-3.0-or-later

//! BIP-32 hardened child key derivation.

use alloc::vec::Vec;
use zkboo::{
    backend::{Allocator, Backend, WordRef},
    word::CompositeWord,
};
use zkboo_hmac::hmac;
use zkboo_sha2::{SHA512_BLOCKSIZE, sha512bytes};

use crate::util::be_bytes_to_word;

/// The smallest hardened child index, `2^31`.
pub const HARDENED_OFFSET: u32 = 0x8000_0000;

/// The secp256k1 group order `n`, as a 4×u64 big-endian constant.
fn order_n() -> CompositeWord<u64, 4> {
    return CompositeWord::from_be_words([
        0xffffffffffffffff,
        0xfffffffffffffffe,
        0xbaaedce6af48a03b,
        0xbfd25e8cd0364141,
    ]);
}

/// Modular addition `(a + b) mod n` for `a, b < n < 2^256`.
///
/// Since both operands are below `n`, their sum is below `2n`, so a single conditional
/// subtraction of `n` reduces the result. (Same shape as `zkboo_modular`'s Montgomery add, which
/// is form-agnostic for addition.)
fn add_mod_n<B: Backend>(a: WordRef<B, u64, 4>, b: WordRef<B, u64, 4>) -> WordRef<B, u64, 4> {
    let n = order_n();
    let (sum, carry) = a.overflowing_add(b);
    return (carry | sum.clone().ge_const(n)).select(sum.clone() - n, sum);
}

/// Derives a BIP-32 **hardened** child private key and chain code.
///
/// Computes `I = HMAC-SHA512(parent_chain_code, 0x00 ‖ ser256(parent_private_key) ‖ ser32(index))`,
/// then `IL = I[0..32]`, the child chain code `IR = I[32..64]`, and the child private key
/// `(parse256(IL) + parent_private_key) mod n` where `n` is the secp256k1 group order.
///
/// `index` must be hardened (`>= 2^31`). The child private key is returned as a 256-bit word
/// (4×u64, little-endian word order); the chain code is returned as 32 big-endian bytes.
///
/// Note: BIP-32 requires `IL < n` and the child key to be non-zero for the index to be valid;
/// both hold with overwhelming probability and are not enforced here. Only hardened derivation is
/// supported — non-hardened derivation requires a SECP256K1 scalar multiplication of the parent
/// private key.
pub fn hardened_child_key<B: Backend>(
    allocator: Allocator<B>,
    parent_chain_code: Vec<WordRef<B, u8>>,
    parent_private_key: Vec<WordRef<B, u8>>,
    index: u32,
) -> (WordRef<B, u64, 4>, [WordRef<B, u8>; 32]) {
    assert!(
        index >= HARDENED_OFFSET,
        "hardened derivation requires index >= 2^31"
    );
    assert_eq!(parent_chain_code.len(), 32, "chain code must be 32 bytes");
    assert_eq!(
        parent_private_key.len(),
        32,
        "parent private key must be 32 bytes"
    );

    // data = 0x00 || ser256(parent_private_key) || ser32(index)
    let mut data: Vec<WordRef<B, u8>> = Vec::with_capacity(37);
    data.push(allocator.alloc(0u8));
    data.extend(parent_private_key.iter().cloned());
    for byte in index.to_be_bytes() {
        data.push(allocator.alloc(byte));
    }

    let i = hmac(
        allocator,
        parent_chain_code,
        data,
        sha512bytes,
        SHA512_BLOCKSIZE,
    );
    let mut words = i.into_iter();
    let il: [WordRef<B, u8>; 32] = core::array::from_fn(|_| words.next().unwrap());
    let ir: [WordRef<B, u8>; 32] = core::array::from_fn(|_| words.next().unwrap());

    let il_word = be_bytes_to_word(&il);
    let parent_word = be_bytes_to_word(&parent_private_key);
    let child_private_key = add_mod_n(il_word, parent_word);

    return (child_private_key, ir);
}
