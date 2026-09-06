// SPDX-License-Identifier: LGPL-3.0-or-later

//! secp256k1 public-key derivation from a private key.

use zkboo::backend::{Backend, Frontend, WordRef};
use zkboo::circuit::Assertions;
use zkboo::word::CompositeWord;
use zkboo_ecc::{
    weierstrass::{ComputedWindowTables, Curve, PointRef, DEFAULT_COMB_WINDOW_BITS, WindowTables},
    secp256k1::{Secp256k1FieldPM, Secp256k1PM},
};
use zkboo_modular::montgomery::MontgomeryWordRef;

/// A secp256k1 point in affine coordinates over the pseudo-Mersenne field.
pub type AffinePoint<B> = (
    MontgomeryWordRef<B, u64, 4, Secp256k1FieldPM>,
    MontgomeryWordRef<B, u64, 4, Secp256k1FieldPM>,
);

/// Derives the secp256k1 public key `Q = d · G` from a private key scalar `d`.
///
/// `private_key_value` is the scalar itself when proving or executing, and `None` when replaying a
/// view, fingerprinting or profiling.
pub fn public_key<B: Backend>(
    frontend: &Frontend<B>,
    private_key: WordRef<B, u64, 4>,
    private_key_value: Option<CompositeWord<u64, 4>>,
    assertions: &mut Assertions<B>,
) -> PointRef<B, u64, 4, Secp256k1PM> {
    let mut tables = ComputedWindowTables::new(Secp256k1PM.g(), DEFAULT_COMB_WINDOW_BITS);
    return public_key_with_tables(
        frontend,
        private_key,
        private_key_value,
        &mut tables,
        assertions,
    );
}

/// [`public_key`], returning the affine coordinates `(x, y)` rather than a point.
pub fn public_key_affine<B: Backend>(
    frontend: &Frontend<B>,
    private_key: WordRef<B, u64, 4>,
    private_key_value: Option<CompositeWord<u64, 4>>,
    assertions: &mut Assertions<B>,
) -> AffinePoint<B> {
    let mut tables = ComputedWindowTables::new(Secp256k1PM.g(), DEFAULT_COMB_WINDOW_BITS);
    return public_key_affine_with_tables(
        frontend,
        private_key,
        private_key_value,
        &mut tables,
        assertions,
    );
}

/// [`public_key_affine`] with a caller-supplied comb-table source.
pub fn public_key_affine_with_tables<B: Backend>(
    frontend: &Frontend<B>,
    private_key: WordRef<B, u64, 4>,
    private_key_value: Option<CompositeWord<u64, 4>>,
    tables: &mut impl WindowTables<u64, 4, Secp256k1PM>,
    assertions: &mut Assertions<B>,
) -> AffinePoint<B> {
    return Secp256k1PM.mul_secret_scalar_affine(
        frontend,
        private_key,
        private_key_value,
        tables,
        assertions,
    );
}

/// [`public_key`] with a caller-supplied comb-table source.
pub fn public_key_with_tables<B: Backend>(
    frontend: &Frontend<B>,
    private_key: WordRef<B, u64, 4>,
    private_key_value: Option<CompositeWord<u64, 4>>,
    tables: &mut impl WindowTables<u64, 4, Secp256k1PM>,
    assertions: &mut Assertions<B>,
) -> PointRef<B, u64, 4, Secp256k1PM> {
    let (x, y) = public_key_affine_with_tables(
        frontend,
        private_key,
        private_key_value,
        tables,
        assertions,
    );
    return PointRef::from_affine(x, y, Secp256k1PM);
}
