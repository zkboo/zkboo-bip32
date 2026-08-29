// SPDX-License-Identifier: LGPL-3.0-or-later

//! secp256k1 public-key derivation from a private key.

use zkboo::backend::{Backend, Frontend, WordRef};
use zkboo::circuit::Assertions;
use zkboo::word::CompositeWord;
use zkboo_ecc::{
    montgomery::{
        AffineCombAdvice, ComputedWindowTables, Curve, CurvePointRef, DEFAULT_COMB_WINDOW_BITS,
        WindowTables,
    },
    secp256k1::{Secp256k1FieldPM, Secp256k1PM},
};
use zkboo_modular::montgomery::MontgomeryWordRef;

/// The advice a public-key derivation needs: one comb slope per window.
pub type PublicKeyAdvice = AffineCombAdvice<u64, 4>;

/// Computes the advice for `d · G` at the default window width, on the host.
pub fn public_key_advice(private_key: CompositeWord<u64, 4>) -> PublicKeyAdvice {
    let mut tables = ComputedWindowTables::new(Secp256k1PM.g(), DEFAULT_COMB_WINDOW_BITS);
    return public_key_advice_with_tables(private_key, &mut tables);
}

/// [`public_key_advice`] with a caller-supplied comb-table source.
pub fn public_key_advice_with_tables(
    private_key: CompositeWord<u64, 4>,
    tables: &mut impl WindowTables<u64, 4, Secp256k1PM>,
) -> PublicKeyAdvice {
    return AffineCombAdvice::compute(Secp256k1PM, private_key, tables);
}

/// The advice's shape without its values, for a verifier, at the default window width.
pub fn public_key_advice_shape() -> PublicKeyAdvice {
    return AffineCombAdvice::zeros(256, DEFAULT_COMB_WINDOW_BITS);
}

/// A secp256k1 point in affine coordinates over the pseudo-Mersenne field.
pub type AffinePoint<B> = (
    MontgomeryWordRef<B, u64, 4, Secp256k1FieldPM>,
    MontgomeryWordRef<B, u64, 4, Secp256k1FieldPM>,
);

/// Derives the secp256k1 public key `Q = d · G` from a private key scalar `d`.
pub fn public_key<B: Backend>(
    frontend: &Frontend<B>,
    private_key: WordRef<B, u64, 4>,
    advice: &PublicKeyAdvice,
    assertions: &mut Assertions<B>,
) -> CurvePointRef<B, u64, 4, Secp256k1PM> {
    let mut tables = ComputedWindowTables::new(Secp256k1PM.g(), DEFAULT_COMB_WINDOW_BITS);
    return public_key_with_tables(frontend, private_key, &mut tables, advice, assertions);
}

/// [`public_key`], returning the affine coordinates `(x, y)` rather than a point.
pub fn public_key_affine<B: Backend>(
    frontend: &Frontend<B>,
    private_key: WordRef<B, u64, 4>,
    advice: &PublicKeyAdvice,
    assertions: &mut Assertions<B>,
) -> AffinePoint<B> {
    let mut tables = ComputedWindowTables::new(Secp256k1PM.g(), DEFAULT_COMB_WINDOW_BITS);
    return public_key_affine_with_tables(frontend, private_key, &mut tables, advice, assertions);
}

/// [`public_key_affine`] with a caller-supplied comb-table source.
pub fn public_key_affine_with_tables<B: Backend>(
    frontend: &Frontend<B>,
    private_key: WordRef<B, u64, 4>,
    tables: &mut impl WindowTables<u64, 4, Secp256k1PM>,
    advice: &PublicKeyAdvice,
    assertions: &mut Assertions<B>,
) -> AffinePoint<B> {
    return Secp256k1PM.mul_secret_scalar_affine(
        frontend,
        private_key,
        tables,
        advice,
        assertions,
    );
}

/// [`public_key`] with a caller-supplied comb-table source.
pub fn public_key_with_tables<B: Backend>(
    frontend: &Frontend<B>,
    private_key: WordRef<B, u64, 4>,
    tables: &mut impl WindowTables<u64, 4, Secp256k1PM>,
    advice: &PublicKeyAdvice,
    assertions: &mut Assertions<B>,
) -> CurvePointRef<B, u64, 4, Secp256k1PM> {
    let (x, y) = public_key_affine_with_tables(frontend, private_key, tables, advice, assertions);
    return CurvePointRef::from_affine(x, y, Secp256k1PM);
}
