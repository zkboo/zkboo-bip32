// SPDX-License-Identifier: LGPL-3.0-or-later

//! What a verifier has to construct, and what it does not.
//!
//! Every secp256k1 derivation here takes the scalar its comb multiplies by twice: once as a circuit
//! input, and once as a host value for the comb to mirror in finding its slopes. A verifier holds
//! neither — a replay discards every input value it is given, and mirrors nothing. This checks that
//! the circuit is the same either way, which is what makes the verifier's obligation nothing more
//! than passing `None`.

use zeroize::Zeroize;
use zkboo::backend::{Backend, Frontend};
use zkboo::circuit::{Assertions, Circuit};
use zkboo::crypto::Hasher;
use zkboo::word::CompositeWord;
use zkboo_bip32::{be_bytes_to_word, ethereum_address, public_key, taproot_output_key};
use zkboo_circuit_hash::hash_circuit;
use zkboo_ecc::weierstrass::PointFrontendIO;

/// A [Hasher] backed by BLAKE3, producing 32-byte digests.
#[derive(Debug)]
struct Blake3Hasher {
    inner: blake3::Hasher,
}

impl Hasher for Blake3Hasher {
    type Digest = [u8; 32];
    const DIGEST_SIZE: usize = 32;

    fn new() -> Self {
        return Self {
            inner: blake3::Hasher::new(),
        };
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize_into(&mut self, out: &mut Self::Digest) {
        let result = self.inner.finalize();
        out.copy_from_slice(result.as_bytes());
        self.inner.reset();
    }
}

impl Zeroize for Blake3Hasher {
    fn zeroize(&mut self) {
        self.inner.reset();
    }
}

/// A statement over a private key, in the two views a prover and a verifier construct.
struct Statement {
    private_key: [u8; 32],
    /// The scalar for the comb to mirror, and `None` in the verifier's view.
    private_key_value: Option<CompositeWord<u64, 4>>,
    /// The Taproot tweak scalar to mirror, and `None` in the verifier's view.
    tweak_scalar_value: Option<CompositeWord<u64, 4>>,
    kind: Kind,
}

#[derive(Clone, Copy)]
enum Kind {
    PublicKey,
    EthereumAddress,
    Taproot,
}

fn be_words(bytes: &[u8; 32]) -> CompositeWord<u64, 4> {
    let mut limbs = [0u64; 4];
    for (i, chunk) in bytes.chunks(8).enumerate() {
        limbs[i] = u64::from_be_bytes(chunk.try_into().expect("eight bytes"));
    }
    return CompositeWord::from_be_words(limbs);
}

impl Statement {
    fn prover(kind: Kind, private_key: [u8; 32]) -> Self {
        let key = be_words(&private_key);
        return Self {
            private_key,
            private_key_value: Some(key),
            // Any value at all: this test compares circuits, which never read an input's value.
            tweak_scalar_value: Some(key),
            kind,
        };
    }

    fn verifier(kind: Kind) -> Self {
        return Self {
            private_key: [0u8; 32],
            private_key_value: None,
            tweak_scalar_value: None,
            kind,
        };
    }
}

impl Circuit for Statement {
    fn exec<B: Backend>(&self, fe: &Frontend<B>) {
        let bytes: Vec<_> = self.private_key.iter().map(|&b| fe.input(b)).collect();
        let scalar = be_bytes_to_word(&bytes);
        Assertions::scope(fe, |asserts| match self.kind {
            Kind::PublicKey => {
                let q = public_key(fe, scalar, self.private_key_value, asserts);
                fe.point_output_affine(q);
            }
            Kind::EthereumAddress => {
                ethereum_address(fe, scalar, self.private_key_value, asserts)
                    .into_iter()
                    .for_each(|w| fe.output(w));
            }
            Kind::Taproot => {
                taproot_output_key(
                    fe,
                    scalar,
                    self.private_key_value,
                    self.tweak_scalar_value,
                    asserts,
                )
                .into_iter()
                .for_each(|w| fe.output(w));
            }
        });
    }
}

#[test]
fn a_verifier_that_mirrors_nothing_runs_the_same_circuit() {
    for kind in [Kind::PublicKey, Kind::EthereumAddress, Kind::Taproot] {
        let mut key = [0u8; 32];
        key[31] = 7;
        assert_eq!(
            hash_circuit::<_, Blake3Hasher>(&Statement::prover(kind, key)),
            hash_circuit::<_, Blake3Hasher>(&Statement::verifier(kind)),
            "holding a scalar to mirror changed the circuit"
        );
    }
}
