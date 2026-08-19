// SPDX-License-Identifier: LGPL-3.0-or-later

//! BIP-39 mnemonic-to-seed derivation (PBKDF2-HMAC-SHA512).

use alloc::vec::Vec;
use zkboo::backend::{Allocator, Backend, WordRef};
use zkboo_sha2::Sha512Hmac;

/// The number of PBKDF2 rounds specified by BIP-39.
pub const PBKDF2_ROUNDS: usize = 2048;

/// The salt prefix specified by BIP-39: the ASCII bytes of `"mnemonic"`, to which the optional
/// passphrase is appended.
pub const SALT_PREFIX: &[u8] = b"mnemonic";

/// Derives the BIP-39 binary seed from a mnemonic via PBKDF2-HMAC-SHA512.
///
/// Computes `PBKDF2(HMAC-SHA512, password = mnemonic, salt = "mnemonic" || passphrase,
/// c = rounds, dkLen = 64)`. Since `dkLen` equals the HMAC-SHA512 output length there is a single
/// PBKDF2 block: `U_1 = HMAC(mnemonic, salt || 0x00000001)`, `U_k = HMAC(mnemonic, U_{k-1})`, and
/// the seed is `U_1 xor U_2 xor … xor U_rounds`.
///
/// `mnemonic` is the password (typically the secret witness — the UTF-8 NFKD bytes of the mnemonic
/// sentence); `salt` is the full public salt `"mnemonic" || passphrase` (UTF-8 NFKD). Pass
/// `rounds = PBKDF2_ROUNDS` for spec-compliant derivation; smaller values are useful for
/// development (a full 2048-round proof is large).
///
/// Note: lifting the full derivation proves knowledge of the mnemonic. To lift a *compromised*
/// seed one instead proves knowledge of the preimage to the last (few) HMAC application(s); that
/// partial variant can be built from the same primitive.
pub fn bip39_seed<B: Backend>(
    allocator: Allocator<B>,
    mnemonic: Vec<WordRef<B, u8>>,
    salt: &[u8],
    rounds: usize,
) -> [WordRef<B, u8>; 64] {
    assert!(rounds >= 1, "PBKDF2 requires at least one round");

    // The HMAC key (the mnemonic) is fixed across all rounds, so cache its ipad/opad midstates
    // once — every round then compresses only its two message blocks.
    let hmac_key = Sha512Hmac::new(allocator.clone(), mnemonic);

    // First block input: salt || INT_32_BE(1).
    let mut block: Vec<WordRef<B, u8>> = salt.iter().map(|&b| allocator.alloc(b)).collect();
    for byte in 1u32.to_be_bytes() {
        block.push(allocator.alloc(byte));
    }

    // U_1 = HMAC-SHA512(mnemonic, salt || 0x00000001).
    let u1 = hmac_key.mac_bytes(allocator.clone(), block);
    let mut acc: [WordRef<B, u8>; 64] = core::array::from_fn(|i| u1[i].clone());
    let mut u_prev: Vec<WordRef<B, u8>> = u1.into_iter().collect();

    // U_k = HMAC-SHA512(mnemonic, U_{k-1}); accumulate the XOR.
    for _ in 1..rounds {
        let u_next = hmac_key.mac_bytes(allocator.clone(), u_prev);
        acc = core::array::from_fn(|i| acc[i].clone() ^ u_next[i].clone());
        u_prev = u_next.into_iter().collect();
    }

    return acc;
}

/// Partial BIP-39 lifting: derives the seed from a late intermediate state, doing only
/// `remaining_rounds` HMAC applications instead of the full 2048.
///
/// PBKDF2's single block is `seed = U_1 xor … xor U_c` with `U_k = HMAC(mnemonic, U_{k-1})`. Given
/// the intermediate `prev_u = U_{k-1}` (64 bytes) and the public running XOR
/// `xor_prefix = U_1 xor … xor U_{k-1}` (64 bytes), this computes `U_k … U_c` (where
/// `remaining_rounds = c - (k-1)`) and returns `xor_prefix xor U_k xor … xor U_c = seed`.
///
/// This realises the whitepaper's "preimage to the last (few) HMAC-SHA512 applications" lifting:
/// the witness is `(mnemonic, prev_u)` and the circuit shrinks from 2048 HMACs to
/// `remaining_rounds`. With `remaining_rounds = 1` it proves knowledge of `U_{2047}` whose final
/// HMAC, XORed with the public prefix, yields the seed.
///
/// ⚠️ The `xor_prefix` is revealed publicly; whether this is acceptable, and exactly which state
/// to treat as the quantum-hard witness, is part of the lifting-protocol design and is not settled
/// here — this provides the circuit building block.
pub fn bip39_seed_partial<B: Backend>(
    allocator: Allocator<B>,
    mnemonic: Vec<WordRef<B, u8>>,
    prev_u: Vec<WordRef<B, u8>>,
    xor_prefix: Vec<WordRef<B, u8>>,
    remaining_rounds: usize,
) -> [WordRef<B, u8>; 64] {
    assert_eq!(prev_u.len(), 64, "prev_u must be 64 bytes");
    assert_eq!(xor_prefix.len(), 64, "xor_prefix must be 64 bytes");
    assert!(remaining_rounds >= 1, "at least one remaining round");

    let hmac_key = Sha512Hmac::new(allocator.clone(), mnemonic);
    let mut acc: [WordRef<B, u8>; 64] = core::array::from_fn(|i| xor_prefix[i].clone());
    let mut u_prev = prev_u;
    for _ in 0..remaining_rounds {
        let u_next = hmac_key.mac_bytes(allocator.clone(), u_prev);
        acc = core::array::from_fn(|i| acc[i].clone() ^ u_next[i].clone());
        u_prev = u_next.into_iter().collect();
    }

    return acc;
}
