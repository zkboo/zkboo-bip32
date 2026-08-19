// SPDX-License-Identifier: LGPL-3.0-or-later

//! Bitcoin address derivation from a private key: legacy/SegWit public-key hashes and the
//! Taproot (BIP-341) key-path output key.
//!
//! Each function returns the *payload* of the address as circuit wires; the textual encoding
//! (Base58Check for P2PKH/P2SH, bech32 for P2WPKH, bech32m for P2TR) is a host-side encoding of
//! that public payload and is out of circuit scope.
//!
//! **Private-key scalar domain.** Every function here takes the private key as a raw 256-bit
//! integer `d` and computes `d·G`, so `d` is used modulo the group order `n`: passing `d ≥ n`
//! yields the same payload as `d mod n` (a valid but non-canonical, non-unique witness), and
//! `d ≡ 0 (mod n)` (i.e. `d ∈ {0, n, 2n}`) makes `d·G` the point at infinity, which — via the
//! `inv(0) = 0` convention in `zkboo-modular` — serializes to a fixed, meaningless sentinel
//! payload rather than erroring. Callers that need a canonical, meaningful statement must
//! constrain the witness to `0 < d < n` (as BIP-32 requires) outside this circuit.

use alloc::vec::Vec;
use zkboo::backend::{Allocator, Backend, Frontend, WordRef};
use zkboo_ecc::montgomery::{
    ComputedWindowTables, Curve, CurvePointRef, DEFAULT_COMB_WINDOW_BITS,
    PointBooleanWordRefSelector, WindowTables,
};
use zkboo_ecc::secp256k1::Secp256k1PM;
use zkboo_ripemd160::ripemd160;
use zkboo_sha2::sha256bytes;

use crate::{
    pubkey::public_key_with_tables,
    util::{be_bytes_to_word, word_to_be_bytes},
};

/// `SHA256("TapTweak")`, the precomputed tag digest of the BIP-341 key-path tweak hash.
///
/// Cross-checked in the tests against the in-circuit SHA-256 of the tag string.
pub const TAP_TWEAK_TAG_HASH: [u8; 32] = [
    0xE8, 0x0F, 0xE1, 0x63, 0x9C, 0x9C, 0xA0, 0x50, 0xE3, 0xAF, 0x1B, 0x39, 0xC1, 0x43, 0xC6, 0x3E,
    0x42, 0x9C, 0xBC, 0xEB, 0x15, 0xD9, 0x40, 0xFB, 0xB5, 0xC5, 0xA1, 0xF4, 0xAF, 0x57, 0xC5, 0xE9,
];

/// Computes Bitcoin's `HASH160 = RIPEMD160(SHA256(msg))`.
pub fn hash160<B: Backend>(
    allocator: Allocator<B>,
    msg: Vec<WordRef<B, u8>>,
) -> [WordRef<B, u8>; 20] {
    let sha = sha256bytes(allocator.clone(), msg);
    return ripemd160(allocator, sha.to_vec());
}

/// Serializes a secp256k1 point as the 33-byte compressed SEC1 encoding
/// `(0x02 | parity(y)) ‖ x_be`.
pub fn compressed_pubkey<B: Backend>(
    point: CurvePointRef<B, u64, 4, Secp256k1PM>,
) -> [WordRef<B, u8>; 33] {
    let (x, y, _, _) = point.to_affine().destructure();
    let parity_byte = y.value().lsb().into() ^ 0x02u8;
    let mut bytes: Vec<WordRef<B, u8>> = Vec::with_capacity(33);
    bytes.push(parity_byte);
    bytes.extend(word_to_be_bytes(x.value()));
    return bytes.try_into().ok().expect("33 pubkey bytes");
}

/// Derives the 20-byte public-key hash `HASH160(compressed pubkey)` for a private key scalar.
///
/// This is the payload of both the P2PKH address (Base58Check with version `0x00`) and the
/// P2WPKH address (SegWit v0 bech32 witness program). Build the scalar from 32 big-endian
/// witness bytes with [be_bytes_to_word](crate::be_bytes_to_word). This convenience form
/// computes the comb tables on demand; use [`pubkey_hash160_with_tables`] to control the table
/// source (e.g. watchdog servicing).
pub fn pubkey_hash160<B: Backend>(
    frontend: &Frontend<B>,
    private_key: WordRef<B, u64, 4>,
) -> [WordRef<B, u8>; 20] {
    let mut tables = ComputedWindowTables::new(Secp256k1PM.g(), DEFAULT_COMB_WINDOW_BITS);
    return pubkey_hash160_with_tables(frontend, private_key, &mut tables);
}

/// [`pubkey_hash160`] with a caller-supplied comb-table source (built for `Secp256k1PM.g()`).
pub fn pubkey_hash160_with_tables<B: Backend>(
    frontend: &Frontend<B>,
    private_key: WordRef<B, u64, 4>,
    tables: &mut impl WindowTables<u64, 4, Secp256k1PM>,
) -> [WordRef<B, u8>; 20] {
    let point = public_key_with_tables(frontend, private_key, tables);
    return hash160(frontend.allocator(), compressed_pubkey(point).to_vec());
}

/// Derives the 20-byte P2SH payload of the wrapped-SegWit `P2SH-P2WPKH` address for a private
/// key scalar: `HASH160(0x0014 ‖ HASH160(compressed pubkey))`.
///
/// The address is the Base58Check encoding of this payload with version `0x05`. This convenience
/// form computes the comb tables on demand; use [`p2sh_p2wpkh_payload_with_tables`] to control
/// the table source.
pub fn p2sh_p2wpkh_payload<B: Backend>(
    frontend: &Frontend<B>,
    private_key: WordRef<B, u64, 4>,
) -> [WordRef<B, u8>; 20] {
    let mut tables = ComputedWindowTables::new(Secp256k1PM.g(), DEFAULT_COMB_WINDOW_BITS);
    return p2sh_p2wpkh_payload_with_tables(frontend, private_key, &mut tables);
}

/// [`p2sh_p2wpkh_payload`] with a caller-supplied comb-table source (built for `Secp256k1PM.g()`).
pub fn p2sh_p2wpkh_payload_with_tables<B: Backend>(
    frontend: &Frontend<B>,
    private_key: WordRef<B, u64, 4>,
    tables: &mut impl WindowTables<u64, 4, Secp256k1PM>,
) -> [WordRef<B, u8>; 20] {
    let allocator = frontend.allocator();
    let key_hash = pubkey_hash160_with_tables(frontend, private_key, tables);
    // redeemScript = OP_0 PUSH20 <key hash>.
    let mut redeem_script: Vec<WordRef<B, u8>> = Vec::with_capacity(22);
    redeem_script.push(allocator.alloc(0x00u8));
    redeem_script.push(allocator.alloc(0x14u8));
    redeem_script.extend(key_hash);
    return hash160(allocator, redeem_script);
}

/// Computes the BIP-340 tagged hash `SHA256(SHA256(tag) ‖ SHA256(tag) ‖ msg)` for a precomputed
/// 32-byte tag digest.
pub fn tagged_hash<B: Backend>(
    allocator: Allocator<B>,
    tag_hash: &[u8; 32],
    msg: Vec<WordRef<B, u8>>,
) -> [WordRef<B, u8>; 32] {
    let mut input: Vec<WordRef<B, u8>> = Vec::with_capacity(64 + msg.len());
    for _ in 0..2 {
        input.extend(tag_hash.iter().map(|&b| allocator.alloc(b)));
    }
    input.extend(msg);
    return sha256bytes(allocator, input);
}

/// Derives the 32-byte Taproot (BIP-341/BIP-86 key-path, no script tree) output-key payload for
/// a private key scalar: `x(Q)` where `Q = lift_x(P) + H_TapTweak(x(P))·G` and `P = d·G`.
///
/// The P2TR address is the bech32m encoding of this payload as a SegWit v1 witness program.
/// `lift_x` (the even-`y` normalization of BIP-340 x-only keys) is realized as a conditional
/// point negation on the parity of `y(P)`. The tweak scalar is used as the full 256-bit hash
/// value: since `t·G = (t mod n)·G`, this matches BIP-341 exactly whenever `t < n`, and deviates
/// only in the `t ≥ n` case that BIP-341 declares invalid (probability ~2⁻¹²⁸, never observed).
///
/// This convenience form computes the comb tables on demand; use
/// [`taproot_output_key_with_tables`] to control the table source.
pub fn taproot_output_key<B: Backend>(
    frontend: &Frontend<B>,
    private_key: WordRef<B, u64, 4>,
) -> [WordRef<B, u8>; 32] {
    let mut tables = ComputedWindowTables::new(Secp256k1PM.g(), DEFAULT_COMB_WINDOW_BITS);
    return taproot_output_key_with_tables(frontend, private_key, &mut tables);
}

/// [`taproot_output_key`] with a caller-supplied comb-table source (built for `Secp256k1PM.g()`).
pub fn taproot_output_key_with_tables<B: Backend>(
    frontend: &Frontend<B>,
    private_key: WordRef<B, u64, 4>,
    tables: &mut impl WindowTables<u64, 4, Secp256k1PM>,
) -> [WordRef<B, u8>; 32] {
    let allocator = frontend.allocator();
    // Internal key P = d·G, normalized to even y (BIP-340 x-only lift).
    let p = public_key_with_tables(frontend, private_key, tables).to_affine();
    let y_is_odd = p.coords()[1].clone().value().lsb();
    let p_even = y_is_odd.point_select(-p.clone(), p);
    let internal_x = word_to_be_bytes(p_even.coords()[0].clone().value());
    // Tweak t = H_TapTweak(x(P)); output key Q = P + t·G.
    let tweak = tagged_hash(allocator, &TAP_TWEAK_TAG_HASH, internal_x);
    let tweak_scalar = be_bytes_to_word(&tweak);
    let q = p_even + Secp256k1PM.mul_secret_scalar(tweak_scalar, tables);
    let (x, _, _, _) = q.to_affine().destructure();
    return word_to_be_bytes(x.value())
        .try_into()
        .ok()
        .expect("32 output-key bytes");
}
