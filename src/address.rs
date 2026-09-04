// SPDX-License-Identifier: LGPL-3.0-or-later

//! Ethereum address derivation from a private key.

use zkboo::backend::{Backend, Frontend, WordRef};
use zkboo::circuit::Assertions;
use zkboo_ecc::weierstrass::{ComputedWindowTables, Curve, DEFAULT_COMB_WINDOW_BITS, WindowTables};
use zkboo_ecc::secp256k1::Secp256k1PM;
use zkboo_keccak::keccak256;

use crate::{
    pubkey::{PublicKeyAdvice, public_key_affine_with_tables},
    util::word_to_be_bytes,
};

/// Derives the 20-byte Ethereum address for a private key scalar `d`.
pub fn ethereum_address<B: Backend>(
    frontend: &Frontend<B>,
    private_key: WordRef<B, u64, 4>,
    advice: &PublicKeyAdvice,
    assertions: &mut Assertions<B>,
) -> [WordRef<B, u8>; 20] {
    let mut tables = ComputedWindowTables::new(Secp256k1PM.g(), DEFAULT_COMB_WINDOW_BITS);
    return ethereum_address_with_tables(frontend, private_key, &mut tables, advice, assertions);
}

/// [`ethereum_address`] with a caller-supplied comb-table source (built for `Secp256k1PM.g()`).
pub fn ethereum_address_with_tables<B: Backend>(
    frontend: &Frontend<B>,
    private_key: WordRef<B, u64, 4>,
    tables: &mut impl WindowTables<u64, 4, Secp256k1PM>,
    advice: &PublicKeyAdvice,
    assertions: &mut Assertions<B>,
) -> [WordRef<B, u8>; 20] {
    let (x, y) =
        public_key_affine_with_tables(frontend, private_key, tables, advice, assertions);

    // Uncompressed public key, no 0x04 prefix: x_be (32) || y_be (32).
    let mut pubkey_bytes = word_to_be_bytes(x.value());
    pubkey_bytes.extend(word_to_be_bytes(y.value()));

    let digest = keccak256(frontend.allocator(), pubkey_bytes);

    // Address = the last 20 bytes of the digest.
    let mut tail = digest.into_iter().skip(12);
    return core::array::from_fn(|_| tail.next().expect("20 address bytes"));
}
