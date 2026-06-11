// SPDX-License-Identifier: LGPL-3.0-or-later

//! Validates BIP-39 seed derivation against the canonical Trezor test vector.
//! See: https://github.com/trezor/python-mnemonic/blob/master/vectors.json (passphrase "TREZOR").

use zkboo::{
    backend::{Backend, Frontend},
    circuit::Circuit,
    executor::{OwnedFlexibleWordPool, exec},
};
use zkboo_bip32::{PBKDF2_ROUNDS, SALT_PREFIX, bip39_seed, bip39_seed_partial};

type WP = OwnedFlexibleWordPool<usize>;

const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon about";
const EXPECTED_SEED: &str = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553\
                             1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";

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

struct PartialSeedCircuit {
    mnemonic: Vec<u8>,
    prev_u: Vec<u8>,
    xor_prefix: Vec<u8>,
    remaining_rounds: usize,
}

impl Circuit for PartialSeedCircuit {
    fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
        let mnemonic = self
            .mnemonic
            .iter()
            .map(|&b| frontend.input(b))
            .collect::<Vec<_>>();
        let prev_u = self
            .prev_u
            .iter()
            .map(|&b| frontend.input(b))
            .collect::<Vec<_>>();
        let xor_prefix = self
            .xor_prefix
            .iter()
            .map(|&b| frontend.alloc(b))
            .collect::<Vec<_>>();
        let seed = bip39_seed_partial(
            frontend.allocator(),
            mnemonic,
            prev_u,
            xor_prefix,
            self.remaining_rounds,
        );
        seed.into_iter().for_each(|w| frontend.output(w));
    }
}

fn to_hex(bytes: &[u8]) -> String {
    return bytes.iter().map(|b| format!("{b:02x}")).collect();
}

#[test]
fn test_bip39_seed_trezor_vector() {
    let mut salt = SALT_PREFIX.to_vec();
    salt.extend_from_slice(b"TREZOR");

    let circuit = SeedCircuit {
        mnemonic: MNEMONIC.as_bytes().to_vec(),
        salt,
        rounds: PBKDF2_ROUNDS,
    };
    let output = exec::<_, WP>(&circuit).u8;

    assert_eq!(output.len(), 64, "expected a 64-byte seed");
    assert_eq!(to_hex(&output), EXPECTED_SEED, "BIP-39 seed");
}

#[test]
fn test_bip39_seed_partial_last_round() {
    // Lift only the last HMAC: prev_u = U_2047, xor_prefix = U_1 xor .. xor U_2047, 1 round.
    let prev_u = from_hex(
        "9a08e6074a4d05a210fe78aee00865dfeb99592f03d8780e7184c0e96764b819\
         c840372afb749213bd50472a14470ae9c8a702b21f9a7c70632203fdad25d6fe",
    );
    let xor_prefix = from_hex(
        "e03e2e97f745b6cf021df91e78635ea2993a798a6d270cd2be6e5073a4e73a78\
         527f99dcab68f4a06fe9f210c67cd0326b56aead9554af41ab2ad39a279b8510",
    );

    let circuit = PartialSeedCircuit {
        mnemonic: MNEMONIC.as_bytes().to_vec(),
        prev_u,
        xor_prefix,
        remaining_rounds: 1,
    };
    let output = exec::<_, WP>(&circuit).u8;

    assert_eq!(output.len(), 64, "expected a 64-byte seed");
    assert_eq!(to_hex(&output), EXPECTED_SEED, "BIP-39 seed (partial lift)");
}

fn from_hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    return (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect();
}
