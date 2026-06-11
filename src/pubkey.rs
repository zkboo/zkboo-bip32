// SPDX-License-Identifier: LGPL-3.0-or-later

//! secp256k1 public-key derivation from a private key.

use zkboo::backend::{Backend, Frontend, WordRef};
use zkboo_ecc::{
    montgomery::{Curve, CurvePointRef, PointFrontendIO},
    secp256k1::Secp256k1,
};

/// Derives the secp256k1 public key `Q = d · G` from a private key scalar `d`.
///
/// The scalar `d` is a 256-bit word (4×u64); build it from 32 big-endian witness bytes with
/// [be_bytes_to_word](crate::be_bytes_to_word). The base point `G` is allocated as a circuit
/// constant. The returned point is in Jacobian coordinates; convert/emit it with
/// [PointFrontendIO::point_output_affine] to obtain the affine `(x, y)`.
///
/// The underlying scalar multiplication is data-oblivious (it conditionally selects at every bit),
/// so it is safe to use with a secret scalar — but note it is the dominant cost of the circuit
/// (~256 point additions + doublings, each several 256-bit field multiplications).
pub fn public_key<B: Backend>(
    frontend: &Frontend<B>,
    private_key: WordRef<B, u64, 4>,
) -> CurvePointRef<B, u64, 4, Secp256k1> {
    let g = frontend.point_alloc(Secp256k1.g());
    return g * private_key;
}
