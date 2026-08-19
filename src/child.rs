// SPDX-License-Identifier: LGPL-3.0-or-later

//! BIP-32 hardened child key derivation.

use alloc::vec::Vec;
use zkboo::{
    backend::{Allocator, Backend, Frontend, WordRef},
    word::CompositeWord,
};
use zkboo_ecc::montgomery::{ComputedWindowTables, Curve, DEFAULT_COMB_WINDOW_BITS, WindowTables};
use zkboo_ecc::secp256k1::Secp256k1PM;
use zkboo_hmac::hmac;
use zkboo_sha2::{SHA512_BLOCKSIZE, sha512bytes};

use crate::{
    pubkey::public_key_with_tables,
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

/// Reduces a 256-bit value modulo `n`. Since any 4×u64 word is `< 2^256 < 2n`, a single
/// conditional subtraction of `n` suffices.
fn reduce_mod_n<B: Backend>(x: WordRef<B, u64, 4>) -> WordRef<B, u64, 4> {
    let n = order_n();
    return x.clone().ge_const(n).select(x.clone() - n, x);
}

/// Modular addition `(a + b) mod n` for arbitrary 256-bit `a, b`.
///
/// Both operands are first reduced mod `n` (a no-op for canonical keys `< n`, but defensive
/// against e.g. an `IL >= n` from HMAC), so their sum is `< 2n` and a single conditional
/// subtraction reduces the result. (Same shape as `zkboo_modular`'s Montgomery add, which is
/// form-agnostic for addition.)
fn add_mod_n<B: Backend>(a: WordRef<B, u64, 4>, b: WordRef<B, u64, 4>) -> WordRef<B, u64, 4> {
    let n = order_n();
    let a = reduce_mod_n(a);
    let b = reduce_mod_n(b);
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

/// Derives a BIP-32 **normal** (non-hardened) child private key and chain code.
///
/// Computes `I = HMAC-SHA512(parent_chain_code, ser_point(parent_pubkey) ‖ ser32(index))`, where
/// `ser_point` is the 33-byte SEC1 *compressed* encoding of the parent public key
/// `parent_private_key · G`; then `IL = I[0..32]`, the child chain code `IR = I[32..64]`, and the
/// child private key `(parse256(IL) + parent_private_key) mod n`.
///
/// `index` must be non-hardened (`< 2^31`). Because it derives the parent public key, this circuit
/// includes a full secp256k1 scalar multiplication (the dominant cost — see
/// [public_key](crate::public_key)). The child private key is returned as a 256-bit word (4×u64);
/// the chain code as 32 big-endian bytes. Validity (`IL < n`, non-zero child) is not enforced.
///
/// This convenience form computes the comb tables on demand; use [`normal_child_key_with_tables`]
/// to control the table source (e.g. watchdog servicing on a secure element).
pub fn normal_child_key<B: Backend>(
    frontend: &Frontend<B>,
    parent_chain_code: Vec<WordRef<B, u8>>,
    parent_private_key: Vec<WordRef<B, u8>>,
    index: u32,
) -> (WordRef<B, u64, 4>, [WordRef<B, u8>; 32]) {
    let mut tables = ComputedWindowTables::new(Secp256k1PM.g(), DEFAULT_COMB_WINDOW_BITS);
    return normal_child_key_with_tables(
        frontend,
        parent_chain_code,
        parent_private_key,
        index,
        &mut tables,
    );
}

/// [`normal_child_key`] with a caller-supplied comb-table source (built for `Secp256k1PM.g()`).
pub fn normal_child_key_with_tables<B: Backend>(
    frontend: &Frontend<B>,
    parent_chain_code: Vec<WordRef<B, u8>>,
    parent_private_key: Vec<WordRef<B, u8>>,
    index: u32,
    tables: &mut impl WindowTables<u64, 4, Secp256k1PM>,
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
    let (x, y, _, _) = public_key_with_tables(frontend, scalar, tables)
        .to_affine()
        .destructure();
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
