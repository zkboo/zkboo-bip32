// SPDX-License-Identifier: LGPL-3.0-or-later

//! BIP-32 hardened child key derivation.

use alloc::vec::Vec;
use zkboo::{
    backend::{Allocator, Backend, Frontend, WordRef},
    circuit::Assertions,
    word::CompositeWord,
};
use zkboo_ecc::weierstrass::{ComputedWindowTables, Curve, DEFAULT_COMB_WINDOW_BITS, WindowTables};
use zkboo_ecc::secp256k1::Secp256k1PM;
use zkboo_hmac::hmac;
use zkboo_sha2::{SHA512_BLOCKSIZE, sha512bytes};

use crate::{
    pubkey::public_key_affine_with_tables,
    util::{be_bytes_to_word, word_to_be_bytes},
};

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

/// Reduces a 256-bit value modulo `n`.
fn reduce_mod_n<B: Backend>(x: WordRef<B, u64, 4>) -> WordRef<B, u64, 4> {
    let n = order_n();
    return x.clone().ge_const(n).select(x.clone() - n, x);
}

/// Modular addition `(a + b) mod n` for arbitrary 256-bit `a, b`.
fn add_mod_n<B: Backend>(a: WordRef<B, u64, 4>, b: WordRef<B, u64, 4>) -> WordRef<B, u64, 4> {
    let n = order_n();
    let a = reduce_mod_n(a);
    let b = reduce_mod_n(b);
    let (sum, carry) = a.overflowing_add(b);
    return (carry | sum.clone().ge_const(n)).select(sum.clone() - n, sum);
}

/// Derives a BIP-32 **hardened** child private key and chain code.
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

/// Derives a BIP-32 **normal** (non-hardened) child private key and chain code.
pub fn normal_child_key<B: Backend>(
    frontend: &Frontend<B>,
    parent_chain_code: Vec<WordRef<B, u8>>,
    parent_private_key: Vec<WordRef<B, u8>>,
    parent_private_key_value: Option<CompositeWord<u64, 4>>,
    index: u32,
    assertions: &mut Assertions<B>,
) -> (WordRef<B, u64, 4>, [WordRef<B, u8>; 32]) {
    let mut tables = ComputedWindowTables::new(Secp256k1PM.g(), DEFAULT_COMB_WINDOW_BITS);
    return normal_child_key_with_tables(
        frontend,
        parent_chain_code,
        parent_private_key,
        parent_private_key_value,
        index,
        &mut tables,
        assertions,
    );
}

/// [`normal_child_key`] with a caller-supplied comb-table source (built for `Secp256k1PM.g()`).
pub fn normal_child_key_with_tables<B: Backend>(
    frontend: &Frontend<B>,
    parent_chain_code: Vec<WordRef<B, u8>>,
    parent_private_key: Vec<WordRef<B, u8>>,
    parent_private_key_value: Option<CompositeWord<u64, 4>>,
    index: u32,
    tables: &mut impl WindowTables<u64, 4, Secp256k1PM>,
    assertions: &mut Assertions<B>,
) -> (WordRef<B, u64, 4>, [WordRef<B, u8>; 32]) {
    assert!(
        index < HARDENED_OFFSET,
        "normal derivation requires index < 2^31"
    );
    assert_eq!(parent_chain_code.len(), 32, "chain code must be 32 bytes");
    assert_eq!(
        parent_private_key.len(),
        32,
        "parent private key must be 32 bytes"
    );

    // Parent public key Q = d·G, in SEC1 compressed form: (0x02 | y_parity) || x_be.
    let scalar = be_bytes_to_word(&parent_private_key);
    let (x, y) = public_key_affine_with_tables(
        frontend,
        scalar,
        parent_private_key_value,
        tables,
        assertions,
    );
    let prefix = y.value().lsb().select_const_const(0x03u8, 0x02u8);
    let x_bytes = word_to_be_bytes(x.value());

    // data = compressed_pubkey (33) || ser32(index) (4).
    let allocator = frontend.allocator();
    let mut data: Vec<WordRef<B, u8>> = Vec::with_capacity(37);
    data.push(prefix);
    data.extend(x_bytes);
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

    let child_private_key = add_mod_n(be_bytes_to_word(&il), be_bytes_to_word(&parent_private_key));
    return (child_private_key, ir);
}
