// SPDX-License-Identifier: LGPL-3.0-or-later

//! SLIP-0010 Ed25519 hierarchical key derivation and Ed25519 public-key derivation, as used by
//! Solana wallets (derivation path `m/44'/501'/account'/0'`, all hardened, from a BIP-39 seed).

use crate::child::HARDENED_OFFSET;
use alloc::vec::Vec;
use core::cell::RefCell;
use zkboo::backend::{Allocator, Backend, BackendHook, Frontend, WordRef};
use zkboo::circuit::{Assertions, Circuit};
use zkboo::executor::{ExecOptions, OwnedFlexibleWordPool, exec};
use zkboo::word::CompositeWord;
use zkboo_ecc::edwards::{
    ComputedWindowTables, Point, PointRef, WindowTables, mul_secret_scalar,
};
use zkboo_modular::montgomery::Montgomery;
use zkboo_hmac::hmac;
use zkboo_sha2::{SHA512_BLOCKSIZE, sha512bytes};

/// The HMAC key of the SLIP-0010 Ed25519 master-key derivation.
pub const SLIP10_ED25519_HMAC_KEY: &[u8] = b"ed25519 seed";

/// The BIP-44 coin type of Solana.
pub const SOLANA_COIN_TYPE: u32 = 501;

/// The comb window width used by the convenience (`*_with_tables`-less) forms.
const WINDOW_BITS: usize = 5;

/// Derives the SLIP-0010 Ed25519 master key and chain code from a seed: `HMAC-SHA512(key = "ed25519
/// seed", seed)`, split in two.
pub fn slip10_ed25519_master<B: Backend>(
    allocator: Allocator<B>,
    seed: Vec<WordRef<B, u8>>,
) -> ([WordRef<B, u8>; 32], [WordRef<B, u8>; 32]) {
    let key = SLIP10_ED25519_HMAC_KEY
        .iter()
        .map(|&b| allocator.alloc(b))
        .collect::<Vec<_>>();
    let i = hmac(allocator, key, seed, sha512bytes, SHA512_BLOCKSIZE);
    let mut words = i.into_iter();
    let il = core::array::from_fn(|_| words.next().expect("64 HMAC bytes"));
    let ir = core::array::from_fn(|_| words.next().expect("64 HMAC bytes"));
    return (il, ir);
}

/// Derives a SLIP-0010 Ed25519 hardened child key and chain code: `HMAC-SHA512(key = chain code,
/// 0x00 ‖ parent key ‖ ser32(index))`, split in two.
pub fn slip10_ed25519_child<B: Backend>(
    allocator: Allocator<B>,
    parent_key: &[WordRef<B, u8>; 32],
    chain_code: &[WordRef<B, u8>; 32],
    index: u32,
) -> ([WordRef<B, u8>; 32], [WordRef<B, u8>; 32]) {
    assert!(
        index < HARDENED_OFFSET,
        "child index must not include the hardened offset"
    );
    let mut msg: Vec<WordRef<B, u8>> = Vec::with_capacity(37);
    msg.push(allocator.alloc(0x00u8));
    msg.extend(parent_key.iter().cloned());
    for byte in (HARDENED_OFFSET + index).to_be_bytes() {
        msg.push(allocator.alloc(byte));
    }
    let key = chain_code.iter().cloned().collect::<Vec<_>>();
    let i = hmac(allocator, key, msg, sha512bytes, SHA512_BLOCKSIZE);
    let mut words = i.into_iter();
    let il = core::array::from_fn(|_| words.next().expect("64 HMAC bytes"));
    let ir = core::array::from_fn(|_| words.next().expect("64 HMAC bytes"));
    return (il, ir);
}

/// Derives the 32-byte Ed25519 public key of a 32-byte secret key (RFC 8032): `A =
/// clamp(SHA-512(key)[0..32]) · B`, returned in compressed encoding.
///
/// `advice` is the affine public key when proving or executing, and `None` when replaying a view,
/// fingerprinting or profiling: the encoding needs affine coordinates, and asserting them costs two
/// field multiplications where computing them costs a modular inversion.
pub fn ed25519_public_key<B: Backend>(
    frontend: &Frontend<B>,
    secret_key: &[WordRef<B, u8>; 32],
    advice: Option<[Montgomery<u64, 4>; 2]>,
    assertions: &mut Assertions<B>,
) -> [WordRef<B, u8>; 32] {
    let mut tables = ComputedWindowTables::new(Point::base(), WINDOW_BITS);
    return ed25519_public_key_with_tables(frontend, secret_key, advice, &mut tables, assertions);
}

/// [`ed25519_public_key`] with a caller-supplied comb-table source (built for
/// [`Point::base`]).
pub fn ed25519_public_key_with_tables<B: Backend>(
    frontend: &Frontend<B>,
    secret_key: &[WordRef<B, u8>; 32],
    advice: Option<[Montgomery<u64, 4>; 2]>,
    tables: &mut impl WindowTables,
    assertions: &mut Assertions<B>,
) -> [WordRef<B, u8>; 32] {
    return ed25519_public_point(frontend, secret_key, tables)
        .compress_advised(frontend, advice, assertions);
}

/// The Ed25519 public point of a 32-byte secret key, before encoding.
fn ed25519_public_point<B: Backend>(
    frontend: &Frontend<B>,
    secret_key: &[WordRef<B, u8>; 32],
    tables: &mut impl WindowTables,
) -> PointRef<B> {
    let digest = sha512bytes(frontend.allocator(), secret_key.to_vec());
    // Clamp the low 32 digest bytes: clear the low 3 bits of byte 0 and the top bit of byte 31,
    // set bit 6 of byte 31; then load as a little-endian 256-bit scalar.
    let mut scalar_bytes: Vec<WordRef<B, u8>> = digest.into_iter().take(32).collect();
    scalar_bytes[0] = (scalar_bytes[0].clone() >> 3) << 3;
    scalar_bytes[31] = ((scalar_bytes[31].clone() << 1) >> 1) | 0x40u8;
    let limbs: [WordRef<B, u64, 1>; 4] = core::array::from_fn(|i| {
        let chunk = scalar_bytes[8 * i..8 * i + 8].to_vec();
        WordRef::<B, u64, 1>::from_le_bytes(chunk)
            .ok()
            .expect("8 bytes per limb")
    });
    let scalar = WordRef::from_le_words(limbs);
    return mul_secret_scalar(scalar, tables);
}

/// Derives the 32-byte Solana public key for `account` from a BIP-39 seed, along the standard
/// wallet path `m/44'/501'/account'/0'`.
pub fn solana_pubkey<B: Backend>(
    frontend: &Frontend<B>,
    seed: Vec<WordRef<B, u8>>,
    account: u32,
    advice: Option<[Montgomery<u64, 4>; 2]>,
    assertions: &mut Assertions<B>,
) -> [WordRef<B, u8>; 32] {
    let mut tables = ComputedWindowTables::new(Point::base(), WINDOW_BITS);
    return solana_pubkey_with_tables(frontend, seed, account, advice, &mut tables, assertions);
}

/// [`solana_pubkey`] with a caller-supplied comb-table source (built for [`Point::base`]).
pub fn solana_pubkey_with_tables<B: Backend>(
    frontend: &Frontend<B>,
    seed: Vec<WordRef<B, u8>>,
    account: u32,
    advice: Option<[Montgomery<u64, 4>; 2]>,
    tables: &mut impl WindowTables,
    assertions: &mut Assertions<B>,
) -> [WordRef<B, u8>; 32] {
    return solana_public_point(frontend, seed, account, tables)
        .compress_advised(frontend, advice, assertions);
}

/// The Solana public point for `account`, before encoding.
fn solana_public_point<B: Backend>(
    frontend: &Frontend<B>,
    seed: Vec<WordRef<B, u8>>,
    account: u32,
    tables: &mut impl WindowTables,
) -> PointRef<B> {
    let allocator = frontend.allocator();
    let (mut key, mut chain) = slip10_ed25519_master(allocator.clone(), seed);
    for index in [44, SOLANA_COIN_TYPE, account, 0] {
        (key, chain) = slip10_ed25519_child(allocator.clone(), &key, &chain, index);
    }
    return ed25519_public_point(frontend, &key, tables);
}

/// The affine Ed25519 public key of a 32-byte secret key, computed on the host.
///
/// The encoding needs affine coordinates and the circuit asserts them rather than computing them,
/// so a prover has to supply them. This mirrors the derivation in cleartext, under the caller's
/// execution options and over the caller's table source.
pub fn ed25519_public_key_affine<T: WindowTables, BH: BackendHook>(
    secret_key: [u8; 32],
    tables: &mut T,
    options: ExecOptions<BH>,
) -> [Montgomery<u64, 4>; 2] {
    return affine_of(
        &Ed25519Affine {
            secret_key,
            tables: RefCell::new(tables),
        },
        options,
    );
}

/// The affine Solana public key for `account`, computed on the host.
///
/// The host counterpart of [`solana_pubkey`], as [`ed25519_public_key_affine`] is of
/// [`ed25519_public_key`].
pub fn solana_pubkey_affine<T: WindowTables, BH: BackendHook>(
    seed: Vec<u8>,
    account: u32,
    tables: &mut T,
    options: ExecOptions<BH>,
) -> [Montgomery<u64, 4>; 2] {
    return affine_of(
        &SolanaAffine {
            seed,
            account,
            tables: RefCell::new(tables),
        },
        options,
    );
}

/// Runs a cleartext pass whose output is a pair of affine coordinates, and reads them back.
fn affine_of<C: Circuit, BH: BackendHook>(
    circuit: &C,
    options: ExecOptions<BH>,
) -> [Montgomery<u64, 4>; 2] {
    let words = exec::<_, OwnedFlexibleWordPool<usize>, _>(circuit, options);
    let limbs = words.as_vec::<u64>();
    assert_eq!(limbs.len(), 8, "two affine coordinates of four limbs each");
    return [
        Montgomery::from_raw(CompositeWord::from_le_words([
            limbs[0], limbs[1], limbs[2], limbs[3],
        ])),
        Montgomery::from_raw(CompositeWord::from_le_words([
            limbs[4], limbs[5], limbs[6], limbs[7],
        ])),
    ];
}

/// The cleartext pass behind [`ed25519_public_key_affine`].
struct Ed25519Affine<'a, T: WindowTables> {
    secret_key: [u8; 32],
    tables: RefCell<&'a mut T>,
}

impl<T: WindowTables> Circuit for Ed25519Affine<'_, T> {
    fn exec<B: Backend>(&self, fe: &Frontend<B>) {
        let key: [WordRef<B, u8>; 32] = core::array::from_fn(|i| fe.input(self.secret_key[i]));
        let mut tables = self.tables.borrow_mut();
        let point = ed25519_public_point(fe, &key, &mut **tables);
        output_affine(fe, point);
    }
}

/// The cleartext pass behind [`solana_pubkey_affine`].
struct SolanaAffine<'a, T: WindowTables> {
    seed: Vec<u8>,
    account: u32,
    tables: RefCell<&'a mut T>,
}

impl<T: WindowTables> Circuit for SolanaAffine<'_, T> {
    fn exec<B: Backend>(&self, fe: &Frontend<B>) {
        let seed: Vec<WordRef<B, u8>> = self.seed.iter().map(|&b| fe.input(b)).collect();
        let mut tables = self.tables.borrow_mut();
        let point = solana_public_point(fe, seed, self.account, &mut **tables);
        output_affine(fe, point);
    }
}

/// Outputs a point's affine coordinates, computing them rather than asserting them: the cleartext
/// passes above exist precisely to produce what the circuit will later assert.
fn output_affine<B: Backend>(fe: &Frontend<B>, point: PointRef<B>) {
    let (x, y) = point.to_affine();
    // The inner Montgomery value, not the canonical residue: this is what the assertion compares
    // against, and what [`PointRef::to_affine_advised`] takes back as advice.
    fe.output(x.into_inner());
    fe.output(y.into_inner());
}
