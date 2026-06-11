// SPDX-License-Identifier: LGPL-3.0-or-later

//! Shared conversion helpers.

use alloc::vec::Vec;
use zkboo::backend::{Backend, WordRef};

/// Assembles 32 big-endian bytes (`bytes[0]` most significant) into a 256-bit word as 4×u64.
///
/// `WordRef::from_be_bytes` only builds a single ≤128-bit word, so the four u64 limbs are
/// assembled individually and combined little-endian-word-first via `from_le_words`: little-endian
/// limb `i` is the big-endian byte group at offset `(3 - i) * 8`.
pub fn be_bytes_to_word<B: Backend>(bytes: &[WordRef<B, u8>]) -> WordRef<B, u64, 4> {
    assert_eq!(bytes.len(), 32, "expected 32 big-endian bytes");
    let words: [WordRef<B, u64, 1>; 4] = core::array::from_fn(|i| {
        let start = (3 - i) * 8;
        let chunk = bytes[start..start + 8].iter().cloned().collect::<Vec<_>>();
        WordRef::<B, u64, 1>::from_be_bytes(chunk).expect("8 bytes per u64 limb")
    });
    return WordRef::from_le_words(words);
}
