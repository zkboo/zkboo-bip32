// SPDX-License-Identifier: LGPL-3.0-or-later

//! Ethereum address derivation from a private key.

use zkboo::backend::{Backend, Frontend, WordRef};
use zkboo_keccak::keccak256;

use crate::{pubkey::public_key, util::word_to_be_bytes};

/// Derives the 20-byte Ethereum address for a private key scalar `d`.
///
/// Computes the public key `Q = d·G`, serialises it as the 64-byte uncompressed encoding
/// `x_be ‖ y_be` (no `0x04` prefix, as Ethereum hashes it), takes its Keccak-256 digest and
/// returns the last 20 bytes.
///
/// Build the scalar from 32 big-endian witness bytes with
/// [be_bytes_to_word](crate::be_bytes_to_word). As with [public_key], the dominant cost is the
/// secp256k1 scalar multiplication.
pub fn ethereum_address<B: Backend>(
    frontend: &Frontend<B>,
    private_key: WordRef<B, u64, 4>,
) -> [WordRef<B, u8>; 20] {
    let (x, y, _, _) = public_key(frontend, private_key).to_affine().destructure();

    // Uncompressed public key, no 0x04 prefix: x_be (32) || y_be (32).
    let mut pubkey_bytes = word_to_be_bytes(x.value());
    pubkey_bytes.extend(word_to_be_bytes(y.value()));

    let digest = keccak256(frontend.allocator(), pubkey_bytes);

    // Address = the last 20 bytes of the digest.
    let mut tail = digest.into_iter().skip(12);
    return core::array::from_fn(|_| tail.next().expect("20 address bytes"));
}
