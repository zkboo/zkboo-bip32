# Changelog

All notable changes to this crate are documented in this file, starting at 1.2.0.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this crate adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Every secp256k1 derivation takes the scalar its comb multiplies by as an optional host value, in place of the table of comb slopes it took before.
  The comb follows the scalar itself, so the slopes exist one at a time inside circuit execution rather than as an object the circuit holds for the length of a proof.
  A caller supplies the value when proving or executing and `None` when verifying, which is the distinction it already draws for every other witness field.
- The Taproot output key takes the tweak scalar as a second optional host value.
  The tweak is derived inside the circuit, so the host can learn it only by mirroring that derivation; `taproot_tweak_scalar` does exactly that, in one cleartext pass over the caller's own table source and under the caller's execution options, so a caller servicing an operating system between backend operations keeps doing so throughout.
- The derivations are unchanged gate for gate, and the known-answer vectors are untouched.

- The Taproot output key and every Ed25519 derivation take the affine point their final conversion produces as advice, and assert it rather than computing a modular inverse.
  `TaprootWitness::compute`, `ed25519_public_key_affine` and `solana_pubkey_affine` mirror the derivations on the host to produce it, each over the caller's table source and under the caller's execution options.
  This recovers a regression that entered when the hint gate was removed: `Point::to_affine` had been hint-backed, and losing the hint added one in-circuit inversion to each of the two statements that convert to affine coordinates.
  Taproot goes from 892,733 AND messages to 800,448 and Solana from 1,212,358 to 1,118,276, both a little below where they stood before the hint gate went.
- Ed25519 derivations take an assertion accumulator, having something to assert for the first time.

- The affine advice is `Montgomery` rather than a bare word, in `TaprootWitness`, `ed25519_public_key_affine`, `solana_pubkey_affine` and the derivations that consume them.

### Removed

- `PublicKeyAdvice`, `public_key_advice`, `public_key_advice_with_tables` and `public_key_advice_shape`.
- `TaprootAdvice`, replaced by `TaprootWitness`, which holds two public quantities — the tweak scalar and the output key — rather than a table of key-equivalent slopes.

## [1.2.0] — 2026-09-04

### Changed

- Adapted to the single entry points for proving, verifying and executing.
- Adapted to the renamed elliptic-curve module and point types in `zkboo-ecc`.
