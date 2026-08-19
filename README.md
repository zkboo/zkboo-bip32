# ZKBoo-BIP32

![Rust](https://img.shields.io/badge/rust-1.92+-orange.svg)

BIP-32 / BIP-39 hierarchical-deterministic key derivation as [ZKBoo](https://crates.io/crates/zkboo)
circuits — the **Proof of Seed** primitives for [ProofofSeed](https://proofofseed.org).

## What this is

Proof of Seed lets a wallet prove, in zero knowledge and with quantum-resistant cryptography,
that it knows the seed (or an intermediate key) from which an account was derived — without
revealing the secret. It is the *signature-lifting* step of the ProofofSeed proposal: a
quantum-weak ECDSA account is "lifted" to a quantum-resistant authentication scheme by proving
knowledge of a pre-image to a hashing step in BIP-32 / BIP-39 key derivation.

These circuits run on the ZKBoo (MPC-in-the-Head) prover, whose memory footprint is small enough
to run **inside a secure element** (a hardware wallet). The resulting proof is not succinct — it is
verified at constant memory by streaming, or recursively lifted to a succinct proof off-device.

## The statements it proves

| Function | Proves knowledge of … | secp256k1? | Validated against |
|---|---|:---:|---|
| `master_key` | a seed → BIP-32 master key ‖ chain code | no | BIP-32 vector 1 |
| `hardened_child_key` | a parent key → hardened child (`(IL+parent) mod n`) | no | BIP-32 vector 1, m/0H |
| `bip39_seed` | a mnemonic → seed (PBKDF2-HMAC-SHA512 ×2048) | no | Trezor vector |
| `bip39_seed_partial` | a mnemonic + late intermediate → seed (last *k* HMACs) | no | Trezor vector |
| `public_key` | a private key → secp256k1 public key `d·G` | **yes** 🐘 | 1·G, 2·G |
| `normal_child_key` | a parent key → non-hardened child | **yes** 🐘 | BIP-32 vector 1, m/0H/1 |
| `ethereum_address` | a private key → Ethereum address `Keccak256(d·G)[12:]` | **yes** 🐘 | privkey 1, 2 |
| `pubkey_hash160` | a private key → Bitcoin P2PKH/P2WPKH payload `HASH160(d·G)` | **yes** 🐘 | BIP-84 vectors, rust-bitcoin |
| `p2sh_p2wpkh_payload` | a private key → Bitcoin wrapped-SegWit P2SH payload | **yes** 🐘 | BIP-49 vector, rust-bitcoin |
| `taproot_output_key` | a private key → Bitcoin Taproot output key (BIP-341/BIP-86) | **yes** 🐘🐘 | BIP-86 vectors, rust-bitcoin |
| `slip10_ed25519_master`/`_child` | a seed → SLIP-0010 Ed25519 hardened chain | no | SLIP-0010 vectors 1–2 |
| `ed25519_public_key` | an Ed25519 secret key → public key (RFC 8032) | ed25519 🐘 | RFC 8032 TEST 1–3 |
| `solana_pubkey` | a seed → Solana public key (`m/44'/501'/account'/0'`) | ed25519 🐘 | wallet-core vector (mnemonic → address, end-to-end in-circuit), SLIP-0010 |

The HMAC-only statements are cheap; the elliptic-curve ones include a scalar multiplication
("the elephant"; the Taproot one includes two) and produce large proofs — but are still
generatable in a secure element and verifiable at constant memory. Address payloads are the
bodies before their public textual encoding (Base58Check / bech32 / bech32m / Base58), which is
host-side. Solana derivation (SLIP-0010) is hardened-only, so its whole chain is HMAC-SHA512
with a single Ed25519 fixed-base multiplication at the end.

## Building blocks

Composes the ZKBoo ecosystem crates: [`zkboo-sha2`](https://crates.io/crates/zkboo-sha2)
(SHA-512), [`zkboo-hmac`](https://crates.io/crates/zkboo-hmac) (HMAC),
[`zkboo-ecc`](https://crates.io/crates/zkboo-ecc) (secp256k1 and Ed25519),
[`zkboo-keccak`](https://crates.io/crates/zkboo-keccak) (Keccak-256), and
[`zkboo-ripemd160`](https://crates.io/crates/zkboo-ripemd160) (RIPEMD-160, for Bitcoin's HASH160).
`be_bytes_to_word` / `word_to_be_bytes` convert between 32 big-endian bytes and a 256-bit (4×u64) word.

## Usage

A circuit derives the public output from a secret witness. For example, proving knowledge of a
seed behind a BIP-32 master key:

```rust
use zkboo::{backend::{Backend, Frontend}, circuit::Circuit};
use zkboo_bip32::master_key;

struct MasterKeyCircuit { seed: Vec<u8> }

impl Circuit for MasterKeyCircuit {
    fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
        let seed = self.seed.iter().map(|&b| frontend.input(b)).collect();   // secret witness
        let (il, ir) = master_key(frontend.allocator(), seed);
        il.into_iter().for_each(|w| frontend.output(w));                       // public output
        ir.into_iter().for_each(|w| frontend.output(w));
    }
}
```

Generate and verify proofs with `zkboo::prover::prove` / `zkboo::verifier::verify` (or the
streaming pipe / `run` harness in `zkboo-harness`). Proofs can be **bound to a message** (e.g. a
transaction hash) so they cannot be replayed to authorise a different operation.

## Benchmarks

Measured locally (release, parallel, BLAKE3, `usize` refcounts; "prover" is the on-device `u8`
estimate). Per-response figures; a full 128-bit-post-quantum proof is `response × 438` independent
responses. These figures cover the original circuits and predate the Bitcoin (HASH160, P2SH,
Taproot) and Solana (Ed25519, SLIP-0010) circuits, which are not yet benchmarked; note also that
`zkboo-harness` now defaults to Keccak-256 as the proof hash, so re-measuring through it reflects
Keccak-256 rather than the BLAKE3 numbers below.

| circuit | response | prover RAM | exec | prove (par) | verify (par) |
|---|---:|---:|---:|---:|---:|
| master key | 57.7 KiB | 12.8 KiB | — | 5.8 ms | 2.0 ms |
| hardened child | 58.1 KiB | 13.3 KiB | — | 5.1 ms | 2.1 ms |
| BIP-39 seed (4 rounds) | 230 KiB | 14.2 KiB | — | 20.1 ms | 7.6 ms |
| secp256k1 pubkey `d·G` | 42.3 MB | 6.0 KiB | — | — | — |
| normal child | 42.3 MB | 13.7 KiB | — | — | — |
| Ethereum address | 42.3 MB | 9.3 KiB | — | — | — |

The headline: **every prover fits a secure element's RAM budget** (single-digit KiB), including the
full Ethereum-address binding. The elephant is proof *size*, not prover memory — and a ~42 MB
response has been streamed and verified end-to-end at constant (~MB) memory. See `zkboo-harness` to reproduce.

## 🚧 Warning 🚧

Work in progress, not yet suitable for production. Security has not been audited; the lifting
protocol details (which intermediate state is the quantum-hard witness, validity enforcement) are
not finalised here.

## License

[LGPLv3 © contributors.](LICENSE)
