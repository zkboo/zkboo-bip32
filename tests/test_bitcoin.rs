// SPDX-License-Identifier: LGPL-3.0-or-later

//! Validates Bitcoin address-payload derivation (P2PKH/P2WPKH public-key hash, P2SH-P2WPKH,
//! Taproot key-path output key) against the reference `bitcoin` (rust-bitcoin) implementation
//! and well-known vectors.

use bitcoin::{
    PublicKey,
    hashes::Hash,
    key::{Secp256k1, TapTweak, UntweakedPublicKey},
    secp256k1::SecretKey,
};
use zkboo::{
    backend::{Backend, Frontend},
    circuit::Circuit,
    executor::{OwnedFlexibleWordPool, exec},
};
use zkboo_bip32::{
    TAP_TWEAK_TAG_HASH, be_bytes_to_word, p2sh_p2wpkh_payload, pubkey_hash160, taproot_output_key,
};

type WP = OwnedFlexibleWordPool<usize>;

#[derive(Clone, Copy)]
enum Payload {
    PubkeyHash,
    P2shP2wpkh,
    Taproot,
}

struct BitcoinCircuit {
    private_key: [u8; 32],
    payload: Payload,
}

impl Circuit for BitcoinCircuit {
    fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
        let bytes = self
            .private_key
            .iter()
            .map(|&b| frontend.input(b))
            .collect::<Vec<_>>();
        let scalar = be_bytes_to_word(&bytes);
        match self.payload {
            Payload::PubkeyHash => pubkey_hash160(frontend, scalar)
                .into_iter()
                .for_each(|w| frontend.output(w)),
            Payload::P2shP2wpkh => p2sh_p2wpkh_payload(frontend, scalar)
                .into_iter()
                .for_each(|w| frontend.output(w)),
            Payload::Taproot => taproot_output_key(frontend, scalar)
                .into_iter()
                .for_each(|w| frontend.output(w)),
        }
    }
}

fn scalar(value: u8) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[31] = value;
    return key;
}

fn run(private_key: [u8; 32], payload: Payload) -> Vec<u8> {
    return exec::<_, WP>(&BitcoinCircuit {
        private_key,
        payload,
    })
    .u8;
}

/// A few fixed test scalars: small ones plus arbitrary 32-byte values, giving both `y` parities.
fn test_scalars() -> Vec<[u8; 32]> {
    let mut scalars = vec![scalar(1), scalar(2), scalar(3)];
    let mut arbitrary = [0x5Au8; 32];
    arbitrary[0] = 0x0C;
    scalars.push(arbitrary);
    scalars.push([0x11u8; 32]);
    return scalars;
}

#[test]
fn test_pubkey_hash160_generator_vector() {
    // The well-known HASH160 of the compressed generator point (private key 1).
    let out = run(scalar(1), Payload::PubkeyHash);
    assert_eq!(
        out.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        "751e76e8199196d454941c45d1b3a323f1433bd6"
    );
}

#[test]
fn test_pubkey_hash160_matches_reference() {
    let secp = Secp256k1::new();
    for key in test_scalars() {
        let sk = SecretKey::from_slice(&key).expect("valid key");
        let expected = PublicKey::new(sk.public_key(&secp)).pubkey_hash();
        let out = run(key, Payload::PubkeyHash);
        assert_eq!(out, expected.as_byte_array().to_vec(), "key {key:02x?}");
    }
}

#[test]
fn test_p2sh_p2wpkh_matches_reference() {
    let secp = Secp256k1::new();
    for key in test_scalars() {
        let sk = SecretKey::from_slice(&key).expect("valid key");
        let pubkey_hash = PublicKey::new(sk.public_key(&secp)).pubkey_hash();
        let mut redeem_script = vec![0x00u8, 0x14u8];
        redeem_script.extend(pubkey_hash.as_byte_array());
        let expected = bitcoin::hashes::hash160::Hash::hash(&redeem_script);
        let out = run(key, Payload::P2shP2wpkh);
        assert_eq!(out, expected.as_byte_array().to_vec(), "key {key:02x?}");
    }
}

#[test]
fn test_taproot_output_key_matches_reference() {
    let secp = Secp256k1::new();
    for key in test_scalars() {
        let sk = SecretKey::from_slice(&key).expect("valid key");
        let (internal, _) = UntweakedPublicKey::from_keypair(&sk.keypair(&secp));
        let (expected, _) = internal.tap_tweak(&secp, None);
        let out = run(key, Payload::Taproot);
        assert_eq!(out, expected.serialize().to_vec(), "key {key:02x?}");
    }
}

#[test]
fn test_tap_tweak_tag_hash_constant() {
    use bitcoin::hashes::{Hash as _, sha256::Hash as Sha256};
    assert_eq!(
        TAP_TWEAK_TAG_HASH,
        Sha256::hash(b"TapTweak").to_byte_array()
    );
}
