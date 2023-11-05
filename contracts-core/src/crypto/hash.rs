//! A generic "backend" or interface for hashing, enabling flexibility between
//! VM-accelerated hashing smart contracts and native hashing in tests

use common::constants::HASH_OUTPUT_SIZE;

pub trait HashBackend {
    fn hash(input: &[u8]) -> [u8; HASH_OUTPUT_SIZE];
}



#[cfg(test)]
pub mod test_helpers {
    use common::constants::HASH_OUTPUT_SIZE;
    use ethers::utils::keccak256;

    use super::HashBackend;

    pub struct TestHasher;

    impl HashBackend for TestHasher {
        fn hash(input: &[u8]) -> [u8; HASH_OUTPUT_SIZE] {
            keccak256(input)
        }
    }
}
