// SPDX-License-Identifier: LGPL-3.0-or-later

//! Validates Ethereum address derivation against well-known private-key → address vectors.

use zkboo::{
    backend::{Backend, Frontend},
    circuit::Circuit,
    executor::{OwnedFlexibleWordPool, exec},
};
use zkboo_bip32::{be_bytes_to_word, ethereum_address};

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
        let address = ethereum_address(frontend, scalar);
        address.into_iter().for_each(|w| frontend.output(w));
    }
}

fn to_hex(bytes: &[u8]) -> String {
    return bytes.iter().map(|b| format!("{b:02x}")).collect();
}

fn address_of(value: u8) -> String {
    let mut private_key = vec![0u8; 32];
    private_key[31] = value;
    let out = exec::<_, WP>(&AddressCircuit { private_key }).u8;
    assert_eq!(out.len(), 20, "expected a 20-byte address");
    return to_hex(&out);
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
