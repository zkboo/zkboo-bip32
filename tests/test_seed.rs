// SPDX-License-Identifier: LGPL-3.0-or-later

//! Validates BIP-39 seed derivation against the canonical Trezor test vector.
//! See: https://github.com/trezor/python-mnemonic/blob/master/vectors.json (passphrase "TREZOR").

use zkboo::{
    backend::{Backend, Frontend},
    circuit::Circuit,
    executor::{OwnedFlexibleWordPool, exec},
};
use zkboo_bip32::{PBKDF2_ROUNDS, SALT_PREFIX, bip39_seed};

type WP = OwnedFlexibleWordPool<usize>;

struct SeedCircuit {
    mnemonic: Vec<u8>,
    salt: Vec<u8>,
    rounds: usize,
}

impl Circuit for SeedCircuit {
    fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
        let mnemonic = self
            .mnemonic
            .iter()
            .map(|&b| frontend.input(b))
            .collect::<Vec<_>>();
        let seed = bip39_seed(frontend.allocator(), mnemonic, &self.salt, self.rounds);
        seed.into_iter().for_each(|w| frontend.output(w));
    }
}

fn to_hex(bytes: &[u8]) -> String {
    return bytes.iter().map(|b| format!("{b:02x}")).collect();
}

#[test]
fn test_bip39_seed_trezor_vector() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon about";
    let passphrase = "TREZOR";
    let expected = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553\
                    1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";

    let mut salt = SALT_PREFIX.to_vec();
    salt.extend_from_slice(passphrase.as_bytes());

    let circuit = SeedCircuit {
        mnemonic: mnemonic.as_bytes().to_vec(),
        salt,
        rounds: PBKDF2_ROUNDS,
    };
    let output = exec::<_, WP>(&circuit).u8;

    assert_eq!(output.len(), 64, "expected a 64-byte seed");
    assert_eq!(to_hex(&output), expected, "BIP-39 seed");
}
