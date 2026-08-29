// SPDX-License-Identifier: LGPL-3.0-or-later

//! Validates Ethereum address derivation against well-known private-key → address vectors.

use zkboo::circuit::Assertions;
use zkboo::word::CompositeWord;
use zkboo::{
    backend::{Backend, Frontend},
    circuit::Circuit,
    executor::{OwnedFlexibleWordPool, exec},
};
use zkboo_bip32::{be_bytes_to_word, ethereum_address, public_key_advice};

/// The private key as a host word: 32 big-endian bytes, four `u64` limbs.
///
/// The prover's view — advice is computed from the witness it already holds.
fn be_words(bytes: &[u8]) -> CompositeWord<u64, 4> {
    let mut limbs = [0u64; 4];
    for (i, chunk) in bytes.chunks(8).enumerate() {
        limbs[i] = u64::from_be_bytes(chunk.try_into().expect("eight bytes"));
    }
    return CompositeWord::from_be_words(limbs);
}


type WP = OwnedFlexibleWordPool<usize>;

struct AddressCircuit {
    private_key: Vec<u8>,
}

impl Circuit for AddressCircuit {
    fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
        let bytes = self
            .private_key
            .iter()
            .map(|&b| frontend.input(b))
            .collect::<Vec<_>>();
        let scalar = be_bytes_to_word(&bytes);
        let mut asserts = Assertions::new();
        let advice = public_key_advice(be_words(&self.private_key));
        let address = ethereum_address(frontend, scalar, &advice, &mut asserts);
        address.into_iter().for_each(|w| frontend.output(w));
        asserts.output(frontend);
    }
}

fn to_hex(bytes: &[u8]) -> String {
    return bytes.iter().map(|b| format!("{b:02x}")).collect();
}

fn address_of(value: u8) -> String {
    let mut private_key = vec![0u8; 32];
    private_key[31] = value;
    let out = exec::<_, WP>(&AddressCircuit { private_key }).u8;
    assert_eq!(out.len(), 21, "expected a 20-byte address and an assertion flag");
    assert_eq!(out[20], 1, "the derivation's assertions did not hold");
    return to_hex(&out[..20]);
}

#[test]
fn test_address_private_key_one() {
    // The well-known address for private key 0x01.
    assert_eq!(address_of(1), "7e5f4552091a69125d5dfcb7b8c2659029395bdf");
}

#[test]
fn test_address_private_key_two() {
    assert_eq!(address_of(2), "2b5ad5c4795c026514f8317c7a215e218dccd6cf");
}
