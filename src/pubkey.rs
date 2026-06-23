// SPDX-License-Identifier: LGPL-3.0-or-later

//! secp256k1 public-key derivation from a private key.

use zkboo::backend::{Backend, Frontend, WordRef};
use zkboo_ecc::{
    montgomery::{Curve, CurvePointRef},
    secp256k1::Secp256k1PM,
};

/// Derives the secp256k1 public key `Q = d · G` from a private key scalar `d`.
///
/// The scalar `d` is a 256-bit word (4×u64); build it from 32 big-endian witness bytes with
/// [be_bytes_to_word](crate::be_bytes_to_word). The returned point is in Jacobian coordinates over
/// the pseudo-Mersenne secp256k1 field; convert/emit it with
/// [PointFrontendIO::point_output_affine](zkboo_ecc::montgomery::PointFrontendIO::point_output_affine)
/// to obtain the affine `(x, y)`.
///
/// This uses the **fixed-base comb** over the **pseudo-Mersenne** field: because `G` is a public
/// constant, every multiple `2^i·G` is precomputed at circuit-build time, so the secret scalar
/// drives only a small number of oblivious table selects and additions — no in-circuit doublings.
/// Together these make the public-key statement roughly an order of magnitude smaller than the
/// generic variable-base double-and-add ladder, while remaining fully data-oblivious.
pub fn public_key<B: Backend>(
    _frontend: &Frontend<B>,
    private_key: WordRef<B, u64, 4>,
) -> CurvePointRef<B, u64, 4, Secp256k1PM> {
    // `G` is a build-time constant, so the fastest data-oblivious multiplication is the fixed-base
    // comb on the constant point (no `point_alloc` of `G`, no in-circuit doublings).
    return Secp256k1PM.g().mul_secret_scalar(private_key);
}
