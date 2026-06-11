// SPDX-License-Identifier: LGPL-3.0-or-later

//! BIP-39 mnemonic-to-seed derivation (PBKDF2-HMAC-SHA512).

use alloc::vec::Vec;
use zkboo::backend::{Allocator, Backend, WordRef};
use zkboo_hmac::hmac;
use zkboo_sha2::{SHA512_BLOCKSIZE, sha512bytes};

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

    // First block input: salt || INT_32_BE(1).
    let mut block: Vec<WordRef<B, u8>> = salt.iter().map(|&b| allocator.alloc(b)).collect();
    for byte in 1u32.to_be_bytes() {
        block.push(allocator.alloc(byte));
    }

    // U_1 = HMAC-SHA512(mnemonic, salt || 0x00000001).
    let u1 = hmac(
        allocator.clone(),
        mnemonic.clone(),
        block,
        sha512bytes,
        SHA512_BLOCKSIZE,
    );
    let mut acc: [WordRef<B, u8>; 64] = core::array::from_fn(|i| u1[i].clone());
    let mut u_prev: Vec<WordRef<B, u8>> = u1.into_iter().collect();

    // U_k = HMAC-SHA512(mnemonic, U_{k-1}); accumulate the XOR.
    for _ in 1..rounds {
        let u_next = hmac(
            allocator.clone(),
            mnemonic.clone(),
            u_prev,
            sha512bytes,
            SHA512_BLOCKSIZE,
        );
        acc = core::array::from_fn(|i| acc[i].clone() ^ u_next[i].clone());
        u_prev = u_next.into_iter().collect();
    }

    return acc;
}
