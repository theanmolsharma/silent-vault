//! BIP340-style tagged hashes as used by BIP352.

use sha2::{Digest, Sha256};

/// Tag for the BIP352 label tweak: `hash_BIP0352/Label(ser256(b_scan) || ser32(m))`.
pub const LABEL_TAG: &str = "BIP0352/Label";

/// `SHA256(SHA256(tag) || SHA256(tag) || parts[0] || parts[1] || ...)`.
pub fn tagged_hash(tag: &str, parts: &[&[u8]]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag.as_bytes());
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_manual_construction() {
        let tag = Sha256::digest(b"BIP0352/Label");
        let mut preimage = Vec::new();
        preimage.extend_from_slice(&tag);
        preimage.extend_from_slice(&tag);
        preimage.extend_from_slice(b"abc");
        preimage.extend_from_slice(&7u32.to_be_bytes());
        let expected: [u8; 32] = Sha256::digest(&preimage).into();
        assert_eq!(tagged_hash(LABEL_TAG, &[b"abc", &7u32.to_be_bytes()]), expected);
    }

    #[test]
    fn parts_are_concatenated() {
        assert_eq!(tagged_hash("t", &[b"ab", b"c"]), tagged_hash("t", &[b"abc"]));
        assert_ne!(tagged_hash("t", &[b"abc"]), tagged_hash("u", &[b"abc"]));
    }
}
