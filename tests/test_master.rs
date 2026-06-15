// SPDX-License-Identifier: LGPL-3.0-or-later

//! Validates master key derivation against BIP-32 test vector 1.
//! See: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vector-1

use zkboo::{
    backend::{Backend, Frontend},
    circuit::Circuit,
    executor::{OwnedFlexibleWordPool, exec},
};
use zkboo_bip32::master_key;

type WP = OwnedFlexibleWordPool<usize>;

/// A circuit deriving the BIP-32 master private key and chain code from a seed witness.
struct MasterKeyCircuit {
    seed: Vec<u8>,
}

impl Circuit for MasterKeyCircuit {
    fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
        let seed = self
            .seed
            .iter()
            .map(|&b| frontend.input(b))
            .collect::<Vec<_>>();
        let (il, ir) = master_key(frontend.allocator(), seed);
        il.into_iter().for_each(|w| frontend.output(w));
        ir.into_iter().for_each(|w| frontend.output(w));
    }
}

fn from_hex(s: &str) -> Vec<u8> {
    return (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect();
}

fn to_hex(bytes: &[u8]) -> String {
    return bytes.iter().map(|b| format!("{b:02x}")).collect();
}

#[test]
fn test_master_key_bip32_vector_1() {
    // BIP-32 test vector 1.
    let seed = from_hex("000102030405060708090a0b0c0d0e0f");
    let expected_il = "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35";
    let expected_ir = "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508";

    let circuit = MasterKeyCircuit { seed };
    let output = exec::<_, WP>(&circuit).u8;

    assert_eq!(output.len(), 64, "expected 64 output bytes (IL || IR)");
    assert_eq!(to_hex(&output[..32]), expected_il, "master private key (IL)");
    assert_eq!(to_hex(&output[32..]), expected_ir, "master chain code (IR)");
}
