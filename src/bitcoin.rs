// SPDX-License-Identifier: LGPL-3.0-or-later

//! Bitcoin address derivation from a private key: legacy/SegWit public-key hashes and the Taproot
//! (BIP-341) key-path output key.

use alloc::vec::Vec;
use zkboo::backend::{Allocator, Backend, Frontend, WordRef};
use zkboo::circuit::Assertions;
use zkboo::executor::{ExecOptions, OwnedFlexibleWordPool, exec};
use zkboo::word::CompositeWord;
use zkboo_ecc::montgomery::{
    ComputedWindowTables, Curve, CurvePointRef, DEFAULT_COMB_WINDOW_BITS,
    PointBooleanWordRefSelector, WindowTables,
};
use zkboo_ecc::secp256k1::Secp256k1PM;
use zkboo_ripemd160::ripemd160;
use zkboo_sha2::sha256bytes;

use crate::{
    pubkey::{
        AffinePoint, PublicKeyAdvice, public_key_advice, public_key_advice_shape,
        public_key_affine_with_tables,
    },
    util::{be_bytes_to_word, word_to_be_bytes},
};

/// `SHA256("TapTweak")`, the precomputed tag digest of the BIP-341 key-path tweak hash.
pub const TAP_TWEAK_TAG_HASH: [u8; 32] = [
    0xE8, 0x0F, 0xE1, 0x63, 0x9C, 0x9C, 0xA0, 0x50, 0xE3, 0xAF, 0x1B, 0x39, 0xC1, 0x43, 0xC6, 0x3E,
    0x42, 0x9C, 0xBC, 0xEB, 0x15, 0xD9, 0x40, 0xFB, 0xB5, 0xC5, 0xA1, 0xF4, 0xAF, 0x57, 0xC5, 0xE9,
];

/// Computes Bitcoin's `HASH160 = RIPEMD160(SHA256(msg))`.
pub fn hash160<B: Backend>(
    allocator: Allocator<B>,
    msg: Vec<WordRef<B, u8>>,
) -> [WordRef<B, u8>; 20] {
    let sha = sha256bytes(allocator.clone(), msg);
    return ripemd160(allocator, sha.to_vec());
}

/// Serialises a secp256k1 point as the 33-byte compressed SEC1 encoding `(0x02 | parity(y)) ‖
/// x_be`.
pub fn compressed_pubkey<B: Backend>(
    point: CurvePointRef<B, u64, 4, Secp256k1PM>,
) -> [WordRef<B, u8>; 33] {
    let (x, y, _, _) = point.to_affine().destructure();
    return compressed_pubkey_affine((x, y));
}

/// [`compressed_pubkey`] from affine coordinates, as
/// [`public_key_affine`](crate::public_key_affine) returns them — no conversion needed.
pub fn compressed_pubkey_affine<B: Backend>(point: AffinePoint<B>) -> [WordRef<B, u8>; 33] {
    let (x, y) = point;
    let parity_byte = y.value().lsb().into() ^ 0x02u8;
    let mut bytes: Vec<WordRef<B, u8>> = Vec::with_capacity(33);
    bytes.push(parity_byte);
    bytes.extend(word_to_be_bytes(x.value()));
    return bytes.try_into().ok().expect("33 pubkey bytes");
}

/// Derives the 20-byte public-key hash `HASH160(compressed pubkey)` for a private key scalar.
pub fn pubkey_hash160<B: Backend>(
    frontend: &Frontend<B>,
    private_key: WordRef<B, u64, 4>,
    advice: &PublicKeyAdvice,
    assertions: &mut Assertions<B>,
) -> [WordRef<B, u8>; 20] {
    let mut tables = ComputedWindowTables::new(Secp256k1PM.g(), DEFAULT_COMB_WINDOW_BITS);
    return pubkey_hash160_with_tables(frontend, private_key, &mut tables, advice, assertions);
}

/// [`pubkey_hash160`] with a caller-supplied comb-table source (built for `Secp256k1PM.g()`).
pub fn pubkey_hash160_with_tables<B: Backend>(
    frontend: &Frontend<B>,
    private_key: WordRef<B, u64, 4>,
    tables: &mut impl WindowTables<u64, 4, Secp256k1PM>,
    advice: &PublicKeyAdvice,
    assertions: &mut Assertions<B>,
) -> [WordRef<B, u8>; 20] {
    let point = public_key_affine_with_tables(frontend, private_key, tables, advice, assertions);
    return hash160(
        frontend.allocator(),
        compressed_pubkey_affine(point).to_vec(),
    );
}

/// Derives the 20-byte P2SH payload of the wrapped-SegWit `P2SH-P2WPKH` address for a private key
/// scalar: `HASH160(0x0014 ‖ HASH160(compressed pubkey))`.
pub fn p2sh_p2wpkh_payload<B: Backend>(
    frontend: &Frontend<B>,
    private_key: WordRef<B, u64, 4>,
    advice: &PublicKeyAdvice,
    assertions: &mut Assertions<B>,
) -> [WordRef<B, u8>; 20] {
    let mut tables = ComputedWindowTables::new(Secp256k1PM.g(), DEFAULT_COMB_WINDOW_BITS);
    return p2sh_p2wpkh_payload_with_tables(frontend, private_key, &mut tables, advice, assertions);
}

/// [`p2sh_p2wpkh_payload`] with a caller-supplied comb-table source (built for `Secp256k1PM.g()`).
pub fn p2sh_p2wpkh_payload_with_tables<B: Backend>(
    frontend: &Frontend<B>,
    private_key: WordRef<B, u64, 4>,
    tables: &mut impl WindowTables<u64, 4, Secp256k1PM>,
    advice: &PublicKeyAdvice,
    assertions: &mut Assertions<B>,
) -> [WordRef<B, u8>; 20] {
    let allocator = frontend.allocator();
    let key_hash =
        pubkey_hash160_with_tables(frontend, private_key, tables, advice, assertions);
    // redeemScript = OP_0 PUSH20 <key hash>.
    let mut redeem_script: Vec<WordRef<B, u8>> = Vec::with_capacity(22);
    redeem_script.push(allocator.alloc(0x00u8));
    redeem_script.push(allocator.alloc(0x14u8));
    redeem_script.extend(key_hash);
    return hash160(allocator, redeem_script);
}

/// Computes the BIP-340 tagged hash `SHA256(SHA256(tag) ‖ SHA256(tag) ‖ msg)` for a precomputed
/// 32-byte tag digest.
pub fn tagged_hash<B: Backend>(
    allocator: Allocator<B>,
    tag_hash: &[u8; 32],
    msg: Vec<WordRef<B, u8>>,
) -> [WordRef<B, u8>; 32] {
    let mut input: Vec<WordRef<B, u8>> = Vec::with_capacity(64 + msg.len());
    for _ in 0..2 {
        input.extend(tag_hash.iter().map(|&b| allocator.alloc(b)));
    }
    input.extend(msg);
    return sha256bytes(allocator, input);
}

/// The advice a Taproot derivation needs: one comb for the internal key, one for the tweak.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaprootAdvice {
    /// The comb for the internal key `P = d·G`.
    internal: PublicKeyAdvice,
    /// The comb for the tweak `t·G`.
    tweak: PublicKeyAdvice,
}

impl TaprootAdvice {
    /// Computes both combs' advice, on the host, from the private key.
    pub fn compute(private_key: CompositeWord<u64, 4>) -> Self {
        let internal = public_key_advice(private_key);
        let scalar = exec::<_, OwnedFlexibleWordPool<usize>, _>(&TweakScalar {
            private_key,
            internal: internal.clone(),
        }, ExecOptions::new());
        let limbs = scalar.as_vec::<u64>();
        assert_eq!(limbs.len(), 4, "the tweak scalar is four 64-bit limbs");
        let tweak_scalar =
            CompositeWord::<u64, 4>::from_le_words([limbs[0], limbs[1], limbs[2], limbs[3]]);
        return Self {
            internal,
            tweak: public_key_advice(tweak_scalar),
        };
    }

    /// Both combs' shape without their values, for a verifier.
    pub fn shape() -> Self {
        return Self {
            internal: public_key_advice_shape(),
            tweak: public_key_advice_shape(),
        };
    }
}

/// The cleartext pass that finds the tweak scalar: everything `taproot_output_key` does up to the
/// tagged hash, with the scalar as its output.
struct TweakScalar {
    private_key: CompositeWord<u64, 4>,
    internal: PublicKeyAdvice,
}

impl zkboo::circuit::Circuit for TweakScalar {
    fn exec<B: Backend>(&self, fe: &Frontend<B>) {
        let mut assertions = Assertions::new();
        let mut tables = ComputedWindowTables::new(Secp256k1PM.g(), DEFAULT_COMB_WINDOW_BITS);
        let private_key = fe.input(self.private_key);
        let (px, py) = public_key_affine_with_tables(
            fe,
            private_key,
            &mut tables,
            &self.internal,
            &mut assertions,
        );
        let p = CurvePointRef::from_affine(px, py, Secp256k1PM);
        let y_is_odd = p.coords()[1].clone().value().lsb();
        let p_even = y_is_odd.point_select(-p.clone(), p);
        let internal_x = word_to_be_bytes(p_even.coords()[0].clone().value());
        let tweak = tagged_hash(fe.allocator(), &TAP_TWEAK_TAG_HASH, internal_x);
        fe.output(be_bytes_to_word(&tweak));
    }
}

/// Derives the 32-byte Taproot (BIP-341/BIP-86 key-path, no script tree) output-key payload for a
/// private key scalar: `x(Q)` where `Q = lift_x(P) + H_TapTweak(x(P))·G` and `P = d·G`.
pub fn taproot_output_key<B: Backend>(
    frontend: &Frontend<B>,
    private_key: WordRef<B, u64, 4>,
    advice: &TaprootAdvice,
    assertions: &mut Assertions<B>,
) -> [WordRef<B, u8>; 32] {
    let mut tables = ComputedWindowTables::new(Secp256k1PM.g(), DEFAULT_COMB_WINDOW_BITS);
    return taproot_output_key_with_tables(frontend, private_key, &mut tables, advice, assertions);
}

/// [`taproot_output_key`] with a caller-supplied comb-table source (built for `Secp256k1PM.g()`).
pub fn taproot_output_key_with_tables<B: Backend>(
    frontend: &Frontend<B>,
    private_key: WordRef<B, u64, 4>,
    tables: &mut impl WindowTables<u64, 4, Secp256k1PM>,
    advice: &TaprootAdvice,
    assertions: &mut Assertions<B>,
) -> [WordRef<B, u8>; 32] {
    let allocator = frontend.allocator();
    // Internal key P = d·G, normalized to even y (BIP-340 x-only lift).
    let (px, py) =
        public_key_affine_with_tables(frontend, private_key, tables, &advice.internal, assertions);
    let p = CurvePointRef::from_affine(px, py, Secp256k1PM);
    let y_is_odd = p.coords()[1].clone().value().lsb();
    let p_even = y_is_odd.point_select(-p.clone(), p);
    let internal_x = word_to_be_bytes(p_even.coords()[0].clone().value());
    // Tweak t = H_TapTweak(x(P)); output key Q = P + t·G.
    let tweak = tagged_hash(allocator, &TAP_TWEAK_TAG_HASH, internal_x);
    let tweak_scalar = be_bytes_to_word(&tweak);
    let (tx, ty) = Secp256k1PM.mul_secret_scalar_affine(
        frontend,
        tweak_scalar,
        tables,
        &advice.tweak,
        assertions,
    );
    let q = p_even + CurvePointRef::from_affine(tx, ty, Secp256k1PM);
    let (x, _, _, _) = q.to_affine().destructure();
    return word_to_be_bytes(x.value())
        .try_into()
        .ok()
        .expect("32 output-key bytes");
}
