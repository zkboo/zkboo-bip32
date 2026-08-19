// SPDX-License-Identifier: LGPL-3.0-or-later

//! secp256k1 public-key derivation from a private key.

use zkboo::backend::{Backend, Frontend, WordRef};
use zkboo_ecc::{
    montgomery::{
        ComputedWindowTables, Curve, CurvePointRef, DEFAULT_COMB_WINDOW_BITS, WindowTables,
    },
    secp256k1::Secp256k1PM,
};

/// Derives the secp256k1 public key `Q = d · G` from a private key scalar `d`.
///
/// `d` is taken as a raw 256-bit integer and used modulo the group order `n`, so `d ≥ n` gives the
/// same key as `d mod n`, and `d ≡ 0 (mod n)` yields the point at infinity (a fixed sentinel, not
/// an error). Callers needing a canonical statement must constrain `0 < d < n` outside the circuit.
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
///
/// This convenience form computes the comb tables on demand at the default window width. To
/// control the table source — e.g. on a secure element, where the native table computation must
/// service a watchdog — use [`public_key_with_tables`].
pub fn public_key<B: Backend>(
    frontend: &Frontend<B>,
    private_key: WordRef<B, u64, 4>,
) -> CurvePointRef<B, u64, 4, Secp256k1PM> {
    let mut tables = ComputedWindowTables::new(Secp256k1PM.g(), DEFAULT_COMB_WINDOW_BITS);
    return public_key_with_tables(frontend, private_key, &mut tables);
}

/// [`public_key`] with a caller-supplied comb-table source. The tables must be built for the
/// secp256k1 base point `G` (e.g. `ComputedWindowTables::new(Secp256k1PM.g(), w)`); their window
/// width sets the gate/memory trade-off, and an on-demand source is where a platform watchdog can
/// be serviced while the public, scalar-independent table multiples are computed.
pub fn public_key_with_tables<B: Backend>(
    _frontend: &Frontend<B>,
    private_key: WordRef<B, u64, 4>,
    tables: &mut impl WindowTables<u64, 4, Secp256k1PM>,
) -> CurvePointRef<B, u64, 4, Secp256k1PM> {
    return Secp256k1PM.mul_secret_scalar(private_key, tables);
}
