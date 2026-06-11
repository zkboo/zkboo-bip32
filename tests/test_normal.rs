// SPDX-License-Identifier: LGPL-3.0-or-later

//! Validates normal (non-hardened) child derivation against BIP-32 test vector 1, chain m/0H/1.
//! See: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vector-1

use zkboo::{
    backend::{Backend, Frontend},
    circuit::Circuit,
    executor::{OwnedFlexibleWordPool, exec},
};
use zkboo_bip32::normal_child_key;

type WP = OwnedFlexibleWordPool<usize>;

struct NormalChildCircuit {
    chain_code: Vec<u8>,
    parent_priv: Vec<u8>,
    index: u32,
}

impl Circuit for NormalChildCircuit {
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
            normal_child_key(frontend, chain_code, parent_priv, self.index);
        frontend.output(child_priv);
        child_chain_code
            .into_iter()
            .for_each(|w| frontend.output(w));
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
fn test_normal_child_bip32_vector_1_m_0h_1() {
    // BIP-32 test vector 1, chain m/0H -> m/0H/1 (normal child, index 1).
    let parent_priv = from_hex("edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea");
    let chain_code = from_hex("47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141");
    let expected_child_priv = "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368";
    let expected_child_chain = "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19";

    let circuit = NormalChildCircuit {
        chain_code,
        parent_priv,
        index: 1,
    };
    let output = exec::<_, WP>(&circuit);

    let w = &output.u64;
    assert_eq!(w.len(), 4, "expected 4 u64 limbs for the child private key");
    let child_priv_hex = format!("{:016x}{:016x}{:016x}{:016x}", w[3], w[2], w[1], w[0]);
    assert_eq!(child_priv_hex, expected_child_priv, "child private key");

    assert_eq!(output.u8.len(), 32, "expected 32 chain-code bytes");
    assert_eq!(to_hex(&output.u8), expected_child_chain, "child chain code");
}
