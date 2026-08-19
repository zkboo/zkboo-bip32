// SPDX-License-Identifier: LGPL-3.0-or-later

//! SLIP-0010 Ed25519 hierarchical key derivation and Ed25519 public-key derivation, as used by
//! Solana wallets (derivation path `m/44'/501'/account'/0'`, all hardened, from a BIP-39 seed).
//!
//! SLIP-0010 restricts Ed25519 to hardened derivation, so the whole chain is HMAC-SHA512 with no
//! elliptic-curve arithmetic; a single fixed-base scalar multiplication turns the derived 32-byte
//! key into the public key `A = clamp(SHA-512(key)[0..32]) · B` (RFC 8032). A Solana address is
//! the Base58 encoding of the 32-byte public key, which is a host-side encoding of the public
//! circuit output.

use crate::child::HARDENED_OFFSET;
use alloc::vec::Vec;
use zkboo::backend::{Allocator, Backend, Frontend, WordRef};
use zkboo_ecc::edwards::{
    ComputedEdwardsWindowTables, EdwardsPoint, EdwardsWindowTables, edwards_mul_secret_scalar,
};
use zkboo_hmac::hmac;
use zkboo_sha2::{SHA512_BLOCKSIZE, sha512bytes};

/// The HMAC key of the SLIP-0010 Ed25519 master-key derivation.
pub const SLIP10_ED25519_HMAC_KEY: &[u8] = b"ed25519 seed";

/// The BIP-44 coin type of Solana.
pub const SOLANA_COIN_TYPE: u32 = 501;

/// The comb window width used by the convenience (`*_with_tables`-less) forms.
const WINDOW_BITS: usize = 5;

/// Derives the SLIP-0010 Ed25519 master key and chain code from a seed:
/// `HMAC-SHA512(key = "ed25519 seed", seed)`, split in two.
///
/// The caller is responsible for allocating `seed` (typically as secret witness inputs via
/// [Frontend::input](zkboo::backend::Frontend::input)).
pub fn slip10_ed25519_master<B: Backend>(
    allocator: Allocator<B>,
    seed: Vec<WordRef<B, u8>>,
) -> ([WordRef<B, u8>; 32], [WordRef<B, u8>; 32]) {
    let key = SLIP10_ED25519_HMAC_KEY
        .iter()
        .map(|&b| allocator.alloc(b))
        .collect::<Vec<_>>();
    let i = hmac(allocator, key, seed, sha512bytes, SHA512_BLOCKSIZE);
    let mut words = i.into_iter();
    let il = core::array::from_fn(|_| words.next().expect("64 HMAC bytes"));
    let ir = core::array::from_fn(|_| words.next().expect("64 HMAC bytes"));
    return (il, ir);
}

/// Derives a SLIP-0010 Ed25519 hardened child key and chain code:
/// `HMAC-SHA512(key = chain code, 0x00 ‖ parent key ‖ ser32(index))`, split in two.
///
/// `index` is the raw child index **without** the hardened offset (Ed25519 supports only
/// hardened derivation, so the offset is added here); it must be below [HARDENED_OFFSET].
pub fn slip10_ed25519_child<B: Backend>(
    allocator: Allocator<B>,
    parent_key: &[WordRef<B, u8>; 32],
    chain_code: &[WordRef<B, u8>; 32],
    index: u32,
) -> ([WordRef<B, u8>; 32], [WordRef<B, u8>; 32]) {
    assert!(
        index < HARDENED_OFFSET,
        "child index must not include the hardened offset"
    );
    let mut msg: Vec<WordRef<B, u8>> = Vec::with_capacity(37);
    msg.push(allocator.alloc(0x00u8));
    msg.extend(parent_key.iter().cloned());
    for byte in (HARDENED_OFFSET + index).to_be_bytes() {
        msg.push(allocator.alloc(byte));
    }
    let key = chain_code.iter().cloned().collect::<Vec<_>>();
    let i = hmac(allocator, key, msg, sha512bytes, SHA512_BLOCKSIZE);
    let mut words = i.into_iter();
    let il = core::array::from_fn(|_| words.next().expect("64 HMAC bytes"));
    let ir = core::array::from_fn(|_| words.next().expect("64 HMAC bytes"));
    return (il, ir);
}

/// Derives the 32-byte Ed25519 public key of a 32-byte secret key (RFC 8032):
/// `A = clamp(SHA-512(key)[0..32]) · B`, returned in compressed encoding.
///
/// This convenience form computes the comb tables on demand; use
/// [`ed25519_public_key_with_tables`] to control the table source.
pub fn ed25519_public_key<B: Backend>(
    frontend: &Frontend<B>,
    secret_key: &[WordRef<B, u8>; 32],
) -> [WordRef<B, u8>; 32] {
    let mut tables = ComputedEdwardsWindowTables::new(EdwardsPoint::base(), WINDOW_BITS);
    return ed25519_public_key_with_tables(frontend, secret_key, &mut tables);
}

/// [`ed25519_public_key`] with a caller-supplied comb-table source (built for
/// [`EdwardsPoint::base`]).
pub fn ed25519_public_key_with_tables<B: Backend>(
    frontend: &Frontend<B>,
    secret_key: &[WordRef<B, u8>; 32],
    tables: &mut impl EdwardsWindowTables,
) -> [WordRef<B, u8>; 32] {
    let digest = sha512bytes(frontend.allocator(), secret_key.to_vec());
    // Clamp the low 32 digest bytes: clear the low 3 bits of byte 0 and the top bit of byte 31,
    // set bit 6 of byte 31; then load as a little-endian 256-bit scalar.
    let mut scalar_bytes: Vec<WordRef<B, u8>> = digest.into_iter().take(32).collect();
    scalar_bytes[0] = (scalar_bytes[0].clone() >> 3) << 3;
    scalar_bytes[31] = ((scalar_bytes[31].clone() << 1) >> 1) | 0x40u8;
    let limbs: [WordRef<B, u64, 1>; 4] = core::array::from_fn(|i| {
        let chunk = scalar_bytes[8 * i..8 * i + 8].to_vec();
        WordRef::<B, u64, 1>::from_le_bytes(chunk)
            .ok()
            .expect("8 bytes per limb")
    });
    let scalar = WordRef::from_le_words(limbs);
    return edwards_mul_secret_scalar(scalar, tables).compress();
}

/// Derives the 32-byte Solana public key for `account` from a BIP-39 seed, along the standard
/// wallet path `m/44'/501'/account'/0'`.
///
/// The Solana address is the Base58 encoding of the returned bytes (host-side). The caller is
/// responsible for allocating `seed` as witness inputs. This convenience form computes the comb
/// tables on demand; use [`solana_pubkey_with_tables`] to control the table source.
pub fn solana_pubkey<B: Backend>(
    frontend: &Frontend<B>,
    seed: Vec<WordRef<B, u8>>,
    account: u32,
) -> [WordRef<B, u8>; 32] {
    let mut tables = ComputedEdwardsWindowTables::new(EdwardsPoint::base(), WINDOW_BITS);
    return solana_pubkey_with_tables(frontend, seed, account, &mut tables);
}

/// [`solana_pubkey`] with a caller-supplied comb-table source (built for [`EdwardsPoint::base`]).
pub fn solana_pubkey_with_tables<B: Backend>(
    frontend: &Frontend<B>,
    seed: Vec<WordRef<B, u8>>,
    account: u32,
    tables: &mut impl EdwardsWindowTables,
) -> [WordRef<B, u8>; 32] {
    let allocator = frontend.allocator();
    let (mut key, mut chain) = slip10_ed25519_master(allocator.clone(), seed);
    for index in [44, SOLANA_COIN_TYPE, account, 0] {
        (key, chain) = slip10_ed25519_child(allocator.clone(), &key, &chain, index);
    }
    return ed25519_public_key_with_tables(frontend, &key, tables);
}
