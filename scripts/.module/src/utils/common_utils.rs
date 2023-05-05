use eyre::Result;
use num_bigint::RandBigInt;
use starknet_crypto::FieldElement;

pub const MAX_FELT_BIT_SIZE: u64 = 251;

pub fn gen_random_felt(bitsize: u64) -> Result<FieldElement> {
    assert!(bitsize <= MAX_FELT_BIT_SIZE);
    let mut rng = rand::thread_rng();
    let mut felt_bytes: Vec<u8> = rng
        .gen_biguint(bitsize)
        // Take in little-endian form
        .to_bytes_le()
        .into_iter()
        // Fill remaining bytes w/ 0s
        .chain(std::iter::repeat(0_u8))
        .take(32)
        .collect();

    // Reverse to get big-endian form
    felt_bytes.reverse();

    Ok(FieldElement::from_byte_slice_be(&felt_bytes)?)
}

pub fn felt_to_dec_str(felt: FieldElement) -> String {
    felt.to_big_decimal(0).to_string()
}
