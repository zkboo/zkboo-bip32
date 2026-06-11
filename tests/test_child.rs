// SPDX-License-Identifier: LGPL-3.0-or-later

//! Validates hardened child derivation against BIP-32 test vector 1, chain m/0H.
//! See: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vector-1

use zkboo::{
    backend::{Backend, Frontend},
    circuit::Circuit,
    executor::{OwnedFlexibleWordPool, exec},
};
use zkboo_bip32::{HARDENED_OFFSET, hardened_child_key};

type WP = OwnedFlexibleWordPool<usize>;

struct HardenedChildCircuit {
    chain_code: Vec<u8>,
    parent_priv: Vec<u8>,
    index: u32,
}

impl Circuit for HardenedChildCircuit {
    fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
        let chain_code = self
            .chain_code
            .iter()
            .map(|&b| frontend.alloc(b))
            .collect::<Vec<_>>();
        let parent_priv = self
            .parent_priv
            .iter()
            .map(|&b| frontend.input(b))
            .collect::<Vec<_>>();
        let (child_priv, child_chain_code) =
            hardened_child_key(frontend.allocator(), chain_code, parent_priv, self.index);
        frontend.output(child_priv); // 4x u64 (little-endian word order)
        child_chain_code
            .into_iter()
            .for_each(|w| frontend.output(w)); // 32x u8
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
fn test_hardened_child_bip32_vector_1_m_0h() {
    // BIP-32 test vector 1, chain m -> m/0H.
    let parent_priv = from_hex("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35");
    let chain_code = from_hex("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508");
    let expected_child_priv = "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea";
    let expected_child_chain = "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141";

    let circuit = HardenedChildCircuit {
        chain_code,
        parent_priv,
        index: HARDENED_OFFSET, // m/0H
    };
    let output = exec::<_, WP>(&circuit);

    // child private key: 4 u64 words in little-endian word order -> big-endian hex.
    let w = &output.u64;
    assert_eq!(w.len(), 4, "expected 4 u64 limbs for the child private key");
    let child_priv_hex = format!("{:016x}{:016x}{:016x}{:016x}", w[3], w[2], w[1], w[0]);
    assert_eq!(child_priv_hex, expected_child_priv, "child private key");

    // child chain code: 32 bytes.
    assert_eq!(output.u8.len(), 32, "expected 32 chain-code bytes");
    assert_eq!(to_hex(&output.u8), expected_child_chain, "child chain code");
}
