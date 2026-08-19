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

// Official test vectors from the BIPs themselves: the published payloads are compared against
// the circuit outputs, with only the secret keys (and address decodings) obtained host-side.

/// The published address's payload: the bytes after the version/opcode prefix of its
/// scriptPubKey (P2WPKH `0014…`, P2SH `a914…87`, P2TR `5120…`).
fn address_payload(address: &str) -> Vec<u8> {
    use std::str::FromStr;
    let script = bitcoin::Address::from_str(address)
        .expect("valid address")
        .assume_checked()
        .script_pubkey();
    let bytes = script.as_bytes();
    return match bytes[0] {
        0x00 | 0x51 => bytes[2..].to_vec(),
        0xa9 => bytes[2..22].to_vec(),
        _ => panic!("unexpected scriptPubKey shape"),
    };
}

#[test]
fn test_taproot_output_key_bip86_vectors() {
    // BIP-86 test vectors: root xprv and published output keys for the first three addresses.
    use std::str::FromStr;
    let secp = Secp256k1::new();
    let root = bitcoin::bip32::Xpriv::from_str(
        "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu",
    )
    .expect("valid root xprv");
    let vectors: [(&str, &str, &str); 3] = [
        (
            "86'/0'/0'/0/0",
            "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c",
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
        ),
        (
            "86'/0'/0'/0/1",
            "a82f29944d65b86ae6b5e5cc75e294ead6c59391a1edc5e016e3498c67fc7bbb",
            "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh",
        ),
        (
            "86'/0'/0'/1/0",
            "882d74e5d0572d5a816cef0041a96b6c1de832f6f9676d9605c44d5e9a97d3dc",
            "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7",
        ),
    ];
    for (path, output_key_hex, address) in vectors {
        let path = bitcoin::bip32::DerivationPath::from_str(path).expect("valid path");
        let key = root
            .derive_priv(&secp, &path)
            .expect("derivable path")
            .private_key
            .secret_bytes();
        let expected: Vec<u8> = (0..32)
            .map(|i| u8::from_str_radix(&output_key_hex[2 * i..2 * i + 2], 16).unwrap())
            .collect();
        assert_eq!(
            expected,
            address_payload(address),
            "vector self-consistency"
        );
        let out = run(key, Payload::Taproot);
        assert_eq!(out, expected, "path {path}");
    }
}

#[test]
fn test_pubkey_hash160_bip84_vectors() {
    // BIP-84 test vectors: published WIF private keys and P2WPKH addresses.
    let vectors: [(&str, &str); 3] = [
        (
            "KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d",
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
        ),
        (
            "Kxpf5b8p3qX56DKEe5NqWbNUP9MnqoRFzZwHRtsFqhzuvUJsYZCy",
            "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g",
        ),
        (
            "KxuoxufJL5csa1Wieb2kp29VNdn92Us8CoaUG3aGtPtcF3AzeXvF",
            "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el",
        ),
    ];
    for (wif, address) in vectors {
        let key = bitcoin::PrivateKey::from_wif(wif)
            .expect("valid WIF")
            .inner
            .secret_bytes();
        let out = run(key, Payload::PubkeyHash);
        assert_eq!(out, address_payload(address), "address {address}");
    }
}

#[test]
fn test_p2sh_p2wpkh_bip49_vector() {
    // BIP-49 test vector: the account-0 first receiving key (testnet; the payload is
    // network-independent).
    let key = bitcoin::PrivateKey::from_wif("cULrpoZGXiuC19Uhvykx7NugygA3k86b3hmdCeyvHYQZSxojGyXJ")
        .expect("valid WIF")
        .inner
        .secret_bytes();
    let out = run(key, Payload::P2shP2wpkh);
    assert_eq!(out, address_payload("2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2"));
}
