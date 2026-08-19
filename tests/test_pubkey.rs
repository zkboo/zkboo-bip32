// SPDX-License-Identifier: LGPL-3.0-or-later

//! Validates secp256k1 public-key derivation `Q = d·G` against known small-scalar points.

use zkboo::{
    backend::{Backend, Frontend},
    circuit::Circuit,
    executor::{OwnedFlexibleWordPool, exec},
};
use zkboo_bip32::{be_bytes_to_word, public_key};
use zkboo_ecc::montgomery::PointFrontendIO;

type WP = OwnedFlexibleWordPool<usize>;

struct PubKeyCircuit {
    private_key: Vec<u8>, // 32 big-endian bytes
}

impl Circuit for PubKeyCircuit {
    fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
        let bytes = self
            .private_key
            .iter()
            .map(|&b| frontend.input(b))
            .collect::<Vec<_>>();
        let scalar = be_bytes_to_word(&bytes);
        let q = public_key(frontend, scalar);
        frontend.point_output_affine(q); // outputs affine x then y (4 u64 limbs each)
    }
}

fn scalar_bytes(value: u8) -> Vec<u8> {
    let mut v = vec![0u8; 32];
    v[31] = value;
    return v;
}

/// Reconstructs a 256-bit big-endian hex string from 4 little-endian-ordered u64 limbs.
fn limbs_to_hex(limbs: &[u64]) -> String {
    return format!(
        "{:016x}{:016x}{:016x}{:016x}",
        limbs[3], limbs[2], limbs[1], limbs[0]
    );
}

fn derive(private_key: Vec<u8>) -> (String, String) {
    let circuit = PubKeyCircuit { private_key };
    let out = exec::<_, WP>(&circuit).u64;
    assert_eq!(out.len(), 8, "expected 8 u64 limbs (affine x ‖ y)");
    return (limbs_to_hex(&out[0..4]), limbs_to_hex(&out[4..8]));
}

#[test]
fn test_pubkey_one_is_generator() {
    // 1 · G = G.
    let (x, y) = derive(scalar_bytes(1));
    assert_eq!(
        x, "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        "x of 1·G"
    );
    assert_eq!(
        y, "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
        "y of 1·G"
    );
}

#[test]
fn test_pubkey_two_is_double_generator() {
    // 2 · G.
    let (x, y) = derive(scalar_bytes(2));
    assert_eq!(
        x, "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
        "x of 2·G"
    );
    assert_eq!(
        y, "1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a",
        "y of 2·G"
    );
}
