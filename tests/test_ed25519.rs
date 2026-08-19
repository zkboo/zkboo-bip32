// SPDX-License-Identifier: LGPL-3.0-or-later

//! Validates Ed25519 public-key derivation against the RFC 8032 test vectors, SLIP-0010 Ed25519
//! derivation against both official SLIP-0010 test vectors (private and public keys at every
//! chain node), and the composed Solana wallet derivation (`m/44'/501'/account'/0'`) against an
//! independently computed expected value.

use zkboo::{
    backend::{Backend, Frontend},
    circuit::Circuit,
    executor::{OwnedFlexibleWordPool, exec},
};
use zkboo_bip32::{
    ed25519_public_key, ed25519_public_key_with_tables, slip10_ed25519_child,
    slip10_ed25519_master, solana_pubkey,
};
use zkboo_ecc::edwards::{ComputedEdwardsWindowTables, EdwardsPoint};

type WP = OwnedFlexibleWordPool<usize>;

fn hex(s: &str) -> Vec<u8> {
    return (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("valid hex"))
        .collect();
}

fn to_hex(bytes: &[u8]) -> String {
    return bytes.iter().map(|b| format!("{b:02x}")).collect();
}

/// Derives the RFC 8032 public key of a fixed secret key.
struct PubkeyCircuit {
    secret_key: Vec<u8>,
}

impl Circuit for PubkeyCircuit {
    fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
        let key: [_; 32] = core::array::from_fn(|i| frontend.input(self.secret_key[i]));
        let pubkey = ed25519_public_key(frontend, &key);
        pubkey.into_iter().for_each(|w| frontend.output(w));
    }
}

/// Walks a SLIP-0010 Ed25519 chain from a seed, outputting the private key and (optionally) the
/// public key at every node, with one shared comb-table source.
struct Slip10Circuit {
    seed: Vec<u8>,
    path: Vec<u32>,
    with_pubkeys: bool,
}

impl Circuit for Slip10Circuit {
    fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
        let allocator = frontend.allocator();
        let seed = self
            .seed
            .iter()
            .map(|&b| frontend.input(b))
            .collect::<Vec<_>>();
        let mut tables = ComputedEdwardsWindowTables::new(EdwardsPoint::base(), 5);
        let (mut key, mut chain) = slip10_ed25519_master(allocator.clone(), seed);
        let mut nodes = vec![key.clone()];
        for &index in &self.path {
            (key, chain) = slip10_ed25519_child(allocator.clone(), &key, &chain, index);
            nodes.push(key.clone());
        }
        for key in nodes {
            key.iter().for_each(|w| frontend.output(w.clone()));
            if self.with_pubkeys {
                ed25519_public_key_with_tables(frontend, &key, &mut tables)
                    .into_iter()
                    .for_each(|w| frontend.output(w));
            }
        }
    }
}

/// Derives the Solana public key for account 0.
struct SolanaCircuit {
    seed: Vec<u8>,
}

impl Circuit for SolanaCircuit {
    fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
        let seed = self
            .seed
            .iter()
            .map(|&b| frontend.input(b))
            .collect::<Vec<_>>();
        let pubkey = solana_pubkey(frontend, seed, 0);
        pubkey.into_iter().for_each(|w| frontend.output(w));
    }
}

#[test]
fn test_ed25519_public_key_rfc8032() {
    // RFC 8032, §7.1, TEST 1-3: secret key → public key.
    let vectors = [
        (
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        ),
        (
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        ),
        (
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        ),
    ];
    for (secret, expected) in vectors {
        let out = exec::<_, WP>(&PubkeyCircuit {
            secret_key: hex(secret),
        })
        .u8;
        assert_eq!(to_hex(&out), expected);
    }
}

/// Checks a SLIP-0010 chain against published (private key, public key) pairs per node; the
/// published public keys carry SLIP-0010's leading 0x00, which is stripped.
fn check_slip10_chain(seed: &str, path: Vec<u32>, nodes: &[(&str, &str)]) {
    let out = exec::<_, WP>(&Slip10Circuit {
        seed: hex(seed),
        path,
        with_pubkeys: true,
    })
    .u8;
    assert_eq!(out.len(), 64 * nodes.len());
    for (i, (key, pubkey)) in nodes.iter().enumerate() {
        assert_eq!(to_hex(&out[64 * i..64 * i + 32]), *key, "node {i} key");
        assert_eq!(
            format!("00{}", to_hex(&out[64 * i + 32..64 * i + 64])),
            *pubkey,
            "node {i} pubkey"
        );
    }
}

#[test]
fn test_slip10_ed25519_vector_1() {
    check_slip10_chain(
        "000102030405060708090a0b0c0d0e0f",
        vec![0, 1, 2, 2, 1000000000],
        &[
            (
                "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7",
                "00a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed",
            ),
            (
                "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3",
                "008c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c",
            ),
            (
                "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2",
                "001932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187",
            ),
            (
                "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9",
                "00ae98736566d30ed0e9d2f4486a64bc95740d89c7db33f52121f8ea8f76ff0fc1",
            ),
            (
                "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662",
                "008abae2d66361c879b900d204ad2cc4984fa2aa344dd7ddc46007329ac76c429c",
            ),
            (
                "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793",
                "003c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a",
            ),
        ],
    );
}

#[test]
fn test_slip10_ed25519_vector_2() {
    check_slip10_chain(
        "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
        vec![0, 2147483647, 1, 2147483646, 2],
        &[
            (
                "171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012",
                "008fe9693f8fa62a4305a140b9764c5ee01e455963744fe18204b4fb948249308a",
            ),
            (
                "1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635",
                "0086fab68dcb57aa196c77c5f264f215a112c22a912c10d123b0d03c3c28ef1037",
            ),
            (
                "ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4",
                "005ba3b9ac6e90e83effcd25ac4e58a1365a9e35a3d3ae5eb07b9e4d90bcf7506d",
            ),
            (
                "3757c7577170179c7868353ada796c839135b3d30554bbb74a4b1e4a5a58505c",
                "002e66aa57069c86cc18249aecf5cb5a9cebbfd6fadeab056254763874a9352b45",
            ),
            (
                "5837736c89570de861ebc173b1086da4f505d4adb387c6a1b1342d5e4ac9ec72",
                "00e33c0f7d81d843c572275f287498e8d408654fdf0d1e065b84e2e6f157aab09b",
            ),
            (
                "551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d",
                "0047150c75db263559a70d5778bf36abbab30fb061ad69f69ece61a72b0cfa4fc0",
            ),
        ],
    );
}

#[test]
fn test_solana_pubkey_independent_expected_value() {
    // The seed is the 64 bytes 0x00..0x3f; the expected public key was computed with an
    // independent implementation (Python hashlib HMAC-SHA512 + affine Edwards arithmetic,
    // itself checked against RFC 8032 TEST 1).
    let seed: Vec<u8> = (0..64u8).collect();
    let out = exec::<_, WP>(&SolanaCircuit { seed }).u8;
    assert_eq!(
        to_hex(&out),
        "ce5e3294aa964334c284d29d498bb3eb5595214ed3b0c96afee36547a938349c"
    );
}

/// Derives a Solana public key fully in-circuit from a mnemonic: BIP-39 seed (all 2048 PBKDF2
/// rounds), then a SLIP-0010 Ed25519 chain, then the Ed25519 public key.
struct MnemonicToPubkeyCircuit {
    mnemonic: &'static str,
    path: Vec<u32>,
}

impl Circuit for MnemonicToPubkeyCircuit {
    fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
        let allocator = frontend.allocator();
        let mnemonic = self
            .mnemonic
            .bytes()
            .map(|b| frontend.input(b))
            .collect::<Vec<_>>();
        let seed = zkboo_bip32::bip39_seed(
            allocator.clone(),
            mnemonic,
            zkboo_bip32::SALT_PREFIX,
            zkboo_bip32::PBKDF2_ROUNDS,
        );
        let (mut key, mut chain) = slip10_ed25519_master(allocator.clone(), seed.to_vec());
        for &index in &self.path {
            (key, chain) = slip10_ed25519_child(allocator.clone(), &key, &chain, index);
        }
        let pubkey = ed25519_public_key(frontend, &key);
        pubkey.into_iter().for_each(|w| frontend.output(w));
    }
}

#[test]
fn test_solana_pubkey_wallet_core_vector() {
    // Public vector from the trust-wallet-core test suite (TWSolanaAddress.HDWallet): this
    // mnemonic at Solana's default derivation path m/44'/501'/0' gives the address
    // 2bUBiBNZyD29gP1oV6de7nxowMLoDBtopMMTGgMvjG5m, whose Base58 decoding is the public key
    // below. The whole pipeline — BIP-39 seed, SLIP-0010 chain, Ed25519 key — runs in-circuit.
    let out = exec::<_, WP>(&MnemonicToPubkeyCircuit {
        mnemonic: "shoot island position soft burden budget tooth cruel issue economy destroy above",
        path: vec![44, 501, 0],
    })
    .u8;
    assert_eq!(
        to_hex(&out),
        "17b02c16bf792e54b606db6c2b10a24647a3e96215f5450186e183f57caaf0d0"
    );
}
