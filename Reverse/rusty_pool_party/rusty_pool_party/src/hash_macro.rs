pub use const_random::const_random;

pub use xxhash_rust::const_xxh3::xxh3_64_with_seed as hasher;

#[macro_export()]
macro_rules! hash_it {
    ($s:expr) => {{
        const EXPR_BYTES: &[u8] = $s.as_bytes();
        const _SEED: u64 = const_random!(u64);
        const _HASH: u64 = $crate::hash_macro::hasher(EXPR_BYTES, _SEED);
        HashSeed {
            hash: _HASH,
            seed: _SEED,
        }
    }};
}
pub struct HashSeed {
    pub hash: u64,
    pub seed: u64,
}
