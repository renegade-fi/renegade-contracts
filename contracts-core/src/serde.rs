//! Custom de/serialization logic used to serialize objects into byte arrays
//! for use in EVM precompiles, transcript operations, and calldata.

use alloc::{vec, vec::Vec};
use alloy_primitives::{Address, U256};
use ark_ec::{short_weierstrass::SWFlags, AffineRepr};
use ark_ff::{BigInteger, MontConfig, PrimeField, Zero};
use ark_serialize::Flags;
use common::{
    constants::{FELT_BYTES, NUM_BYTES_U256, NUM_SELECTORS, NUM_U64S_FELT, NUM_WIRE_TYPES},
    types::{
        ExternalTransfer, G1Affine, G1BaseField, G2Affine, G2BaseField, MatchPayload, MontFp256,
        Proof, PublicSigningKey, ScalarField, ValidCommitmentsStatement, ValidMatchSettleStatement,
        ValidReblindStatement, ValidWalletCreateStatement, ValidWalletUpdateStatement,
        VerificationKey,
    },
};

// -------------------------------
// | BYTE SERDE TRAIT DEFINITION |
// -------------------------------

// TODO: Implement derive macros for `Serializable` and `Deserializable`

#[derive(Debug)]
pub struct SerdeError;

pub trait Serializable {
    /// Serializes a type into a vector of bytes
    fn serialize(&self) -> Vec<u8>;
}

pub trait Deserializable {
    const SER_LEN: usize;

    /// Deserializes a type from a slice of bytes
    fn deserialize(bytes: &[u8]) -> Result<Self, SerdeError>
    where
        Self: Sized;
}

pub struct TranscriptG1(pub G1Affine);

// -------------------------
// | TRAIT IMPLEMENTATIONS |
// -------------------------

impl Serializable for bool {
    fn serialize(&self) -> Vec<u8> {
        vec![*self as u8]
    }
}

impl Serializable for u64 {
    fn serialize(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
}

impl Deserializable for u64 {
    const SER_LEN: usize = 8;

    fn deserialize(bytes: &[u8]) -> Result<Self, SerdeError> {
        Ok(u64::from_be_bytes(
            bytes.try_into().map_err(|_| SerdeError)?,
        ))
    }
}

impl<P: MontConfig<NUM_U64S_FELT>> Serializable for MontFp256<P> {
    /// Serializes a field element into a big-endian byte array
    fn serialize(&self) -> Vec<u8> {
        self.into_bigint().to_bytes_be()
    }
}

impl<P: MontConfig<NUM_U64S_FELT>> Deserializable for MontFp256<P> {
    const SER_LEN: usize = FELT_BYTES;

    fn deserialize(bytes: &[u8]) -> Result<Self, SerdeError> {
        Ok(Self::from_be_bytes_mod_order(bytes))
    }
}

impl Serializable for G1Affine {
    /// Serializes a G1 point into a big-endian byte array of its coordinates.
    ///
    /// This matches the format expected by the EVM `ecAdd`, `ecMul`, and `ecPairing`
    /// precompiles as specified here:
    /// https://eips.ethereum.org/EIPS/eip-197#encoding
    fn serialize(&self) -> Vec<u8> {
        let zero = G1BaseField::zero();
        let (x, y) = self.xy().unwrap_or((&zero, &zero));
        [x, y]
            .into_iter()
            .flat_map(Serializable::serialize)
            .collect()
    }
}

impl Deserializable for G1Affine {
    const SER_LEN: usize = FELT_BYTES * 2;

    /// Deserializes a G1 point from a byte array.
    ///
    /// This matches the format returned by the EVM `ecAdd` and `ecMul` precompiles,
    /// as specified here:
    /// https://eips.ethereum.org/EIPS/eip-196#encoding
    fn deserialize(bytes: &[u8]) -> Result<Self, SerdeError> {
        // Note: although this performs modular reduction, it's safe to do so
        // since we can assume that precompiles will always correctly return
        // elements contained in the field
        let mut cursor = 0;
        let x = deserialize_cursor(bytes, &mut cursor)?;
        let y = deserialize_cursor(bytes, &mut cursor)?;

        Ok(G1Affine {
            x,
            y,
            infinity: x.is_zero() && y.is_zero(),
        })
    }
}

impl Serializable for TranscriptG1 {
    /// Replicates the functionality of `serialize_compressed` for `Affine`
    fn serialize(&self) -> Vec<u8> {
        let (x, flags) = match self.0.infinity {
            true => (G1BaseField::zero(), SWFlags::infinity()),
            false => (self.0.x, self.0.to_flags()),
        };

        let mut x_bytes = x.into_bigint().to_bytes_le();
        x_bytes[FELT_BYTES - 1] |= flags.u8_bitmask();

        x_bytes
    }
}

impl Serializable for G2Affine {
    /// Serializes a G2 point into a big-endian byte array of the coefficients
    /// of its coordinates in the extension field, i.e.:
    ///
    /// Given an element of the field extension F_p^2[i] represented as ai + b, where a and b are elements
    /// of F_p, its serialization is the concatenation of a and b in big-endian order.
    ///
    /// This matches the format expected by the EVM `ecPairing` precompile, as specified here:
    /// https://eips.ethereum.org/EIPS/eip-197#encoding
    fn serialize(&self) -> Vec<u8> {
        let zero = G2BaseField::zero();
        let (x, y) = self.xy().unwrap_or((&zero, &zero));
        [x.c1, x.c0, y.c1, y.c0]
            .iter()
            .flat_map(|f| f.into_bigint().to_bytes_be())
            .collect()
    }
}

impl Deserializable for G2Affine {
    const SER_LEN: usize = FELT_BYTES * 4;

    fn deserialize(bytes: &[u8]) -> Result<Self, SerdeError> {
        let mut cursor = 0;
        let x_c1 = deserialize_cursor(bytes, &mut cursor)?;
        let x_c0 = deserialize_cursor(bytes, &mut cursor)?;
        let y_c1 = deserialize_cursor(bytes, &mut cursor)?;
        let y_c0 = deserialize_cursor(bytes, &mut cursor)?;

        let x = G2BaseField { c0: x_c0, c1: x_c1 };
        let y = G2BaseField { c0: y_c0, c1: y_c1 };

        Ok(G2Affine {
            x,
            y,
            infinity: x.is_zero() && y.is_zero(),
        })
    }
}

impl Serializable for VerificationKey {
    fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(self.n.serialize());
        bytes.extend(self.l.serialize());
        bytes.extend(self.k.iter().flat_map(Serializable::serialize));
        bytes.extend(self.q_comms.iter().flat_map(Serializable::serialize));
        bytes.extend(self.sigma_comms.iter().flat_map(Serializable::serialize));
        bytes.extend(self.g.serialize());
        bytes.extend(self.h.serialize());
        bytes.extend(self.x_h.serialize());
        bytes
    }
}

impl Deserializable for VerificationKey {
    const SER_LEN: usize =
        // n, l
        u64::SER_LEN * 2
        // k
        + ScalarField::SER_LEN * NUM_WIRE_TYPES
        // q_comms, sigma_comms, g
        + G1Affine::SER_LEN * (NUM_SELECTORS + NUM_WIRE_TYPES + 1)
        // h, x_H
        + G2Affine::SER_LEN * 2;

    fn deserialize(bytes: &[u8]) -> Result<Self, SerdeError> {
        let mut cursor: usize = 0;

        Ok(VerificationKey {
            n: deserialize_cursor(bytes, &mut cursor)?,
            l: deserialize_cursor(bytes, &mut cursor)?,
            k: deserialize_cursor(bytes, &mut cursor)?,
            q_comms: deserialize_cursor(bytes, &mut cursor)?,
            sigma_comms: deserialize_cursor(bytes, &mut cursor)?,
            g: deserialize_cursor(bytes, &mut cursor)?,
            h: deserialize_cursor(bytes, &mut cursor)?,
            x_h: deserialize_cursor(bytes, &mut cursor)?,
        })
    }
}

impl Serializable for Proof {
    fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(self.wire_comms.iter().flat_map(Serializable::serialize));
        bytes.extend(self.z_comm.serialize());
        bytes.extend(self.quotient_comms.iter().flat_map(Serializable::serialize));
        bytes.extend(self.w_zeta.serialize());
        bytes.extend(self.w_zeta_omega.serialize());
        bytes.extend(self.wire_evals.iter().flat_map(Serializable::serialize));
        bytes.extend(self.sigma_evals.iter().flat_map(Serializable::serialize));
        bytes.extend(self.z_bar.serialize());
        bytes
    }
}

impl Deserializable for Proof {
    const SER_LEN: usize =
        // wire_comms, z_comm, quotient_comms, w_zeta, w_zeta_omega
        G1Affine::SER_LEN * (NUM_WIRE_TYPES * 2 + 3)
        // wire_evals, sigma_evals, z_bar
        + ScalarField::SER_LEN * (NUM_WIRE_TYPES * 2);

    fn deserialize(bytes: &[u8]) -> Result<Self, SerdeError> {
        let mut cursor: usize = 0;

        Ok(Proof {
            wire_comms: deserialize_cursor(bytes, &mut cursor)?,
            z_comm: deserialize_cursor(bytes, &mut cursor)?,
            quotient_comms: deserialize_cursor(bytes, &mut cursor)?,
            w_zeta: deserialize_cursor(bytes, &mut cursor)?,
            w_zeta_omega: deserialize_cursor(bytes, &mut cursor)?,
            wire_evals: deserialize_cursor(bytes, &mut cursor)?,
            sigma_evals: deserialize_cursor(bytes, &mut cursor)?,
            z_bar: deserialize_cursor(bytes, &mut cursor)?,
        })
    }
}

impl Serializable for Address {
    fn serialize(&self) -> Vec<u8> {
        self.into_array().to_vec()
    }
}

impl Serializable for U256 {
    fn serialize(&self) -> Vec<u8> {
        let bytes: [u8; NUM_BYTES_U256] = self.to_be_bytes();
        bytes.to_vec()
    }
}

impl Serializable for ExternalTransfer {
    fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(self.account_addr.serialize());
        bytes.extend(self.mint.serialize());
        bytes.extend(self.amount.serialize());
        bytes.extend(self.is_withdrawal.serialize());
        bytes
    }
}

impl Serializable for PublicSigningKey {
    fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(self.x.as_slice().serialize());
        bytes.extend(self.y.as_slice().serialize());
        bytes
    }
}

impl Serializable for ValidWalletCreateStatement {
    fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(self.private_shares_commitment.serialize());
        bytes.extend(self.public_wallet_shares.as_slice().serialize());
        bytes
    }
}

impl Serializable for ValidWalletUpdateStatement {
    fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(self.old_shares_nullifier.serialize());
        bytes.extend(self.new_private_shares_commitment.serialize());
        bytes.extend(self.new_public_shares.as_slice().serialize());
        bytes.extend(self.merkle_root.serialize());
        bytes.extend(self.external_transfer.serialize());
        bytes.extend(self.old_pk_root.serialize());
        bytes.extend(self.timestamp.serialize());
        bytes
    }
}

impl Serializable for ValidReblindStatement {
    fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(self.original_shares_nullifier.serialize());
        bytes.extend(self.reblinded_private_shares_commitment.serialize());
        bytes.extend(self.merkle_root.serialize());
        bytes
    }
}

impl Serializable for ValidCommitmentsStatement {
    fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(self.balance_send_index.serialize());
        bytes.extend(self.balance_receive_index.serialize());
        bytes.extend(self.order_index.serialize());
        bytes
    }
}

impl Serializable for ValidMatchSettleStatement {
    fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(self.party0_modified_shares.as_slice().serialize());
        bytes.extend(self.party1_modified_shares.as_slice().serialize());
        bytes.extend(self.party0_send_balance_index.serialize());
        bytes.extend(self.party0_receive_balance_index.serialize());
        bytes.extend(self.party0_order_index.serialize());
        bytes.extend(self.party1_send_balance_index.serialize());
        bytes.extend(self.party1_receive_balance_index.serialize());
        bytes.extend(self.party1_order_index.serialize());
        bytes
    }
}

impl Serializable for MatchPayload {
    fn serialize(&self) -> Vec<u8> {
        let mut bytes = self.wallet_blinder_share.serialize();
        bytes.extend(self.valid_commitments_statement.serialize());
        bytes.extend(self.valid_commitments_proof.serialize());
        bytes.extend(self.valid_reblind_statement.serialize());
        bytes.extend(self.valid_reblind_proof.serialize());
        bytes
    }
}

// ---------------------------------
// | SCALAR SERDE TRAIT DEFINITION |
// ---------------------------------

#[derive(Debug)]
pub struct ScalarSerdeError;

pub trait ScalarSerializable {
    /// Serializes a type into a vector of scalars
    fn to_scalars(&self) -> Vec<ScalarField>;
}

pub trait ScalarDeserializable {
    /// Deserializes a type from a slice of scalars
    fn from_scalars(scalars: &[ScalarField]) -> Result<Self, ScalarSerdeError>
    where
        Self: Sized;
}

// -------------------------
// | TRAIT IMPLEMENTATIONS |
// -------------------------

impl ScalarSerializable for bool {
    fn to_scalars(&self) -> Vec<ScalarField> {
        vec![(*self).into()]
    }
}

impl ScalarSerializable for u64 {
    fn to_scalars(&self) -> Vec<ScalarField> {
        vec![(*self).into()]
    }
}

impl ScalarSerializable for Address {
    fn to_scalars(&self) -> Vec<ScalarField> {
        // It's safe to perform modular reduction here since an address is 20 bytes
        // and as such fits within the scalar field modulus
        vec![ScalarField::from_be_bytes_mod_order(&self.into_array())]
    }
}

impl ScalarSerializable for U256 {
    fn to_scalars(&self) -> Vec<ScalarField> {
        // Need to split the U256 into two 128-bit chunks to fit into the scalar field
        let bytes: [u8; NUM_BYTES_U256] = self.to_be_bytes();
        vec![
            ScalarField::from_be_bytes_mod_order(&bytes[..NUM_BYTES_U256 / 2]),
            ScalarField::from_be_bytes_mod_order(&bytes[NUM_BYTES_U256 / 2..]),
        ]
    }
}

impl ScalarSerializable for ExternalTransfer {
    fn to_scalars(&self) -> Vec<ScalarField> {
        let mut scalars = Vec::new();
        scalars.extend(self.account_addr.to_scalars());
        scalars.extend(self.mint.to_scalars());
        scalars.extend(self.amount.to_scalars());
        scalars.extend(self.is_withdrawal.to_scalars());
        scalars
    }
}

impl ScalarSerializable for PublicSigningKey {
    fn to_scalars(&self) -> Vec<ScalarField> {
        let mut scalars = Vec::new();
        scalars.extend(self.x);
        scalars.extend(self.y);
        scalars
    }
}

impl ScalarSerializable for ValidWalletCreateStatement {
    fn to_scalars(&self) -> Vec<ScalarField> {
        let mut scalars = vec![self.private_shares_commitment];
        scalars.extend(self.public_wallet_shares);
        scalars
    }
}

impl ScalarSerializable for ValidWalletUpdateStatement {
    fn to_scalars(&self) -> Vec<ScalarField> {
        let mut scalars = vec![
            self.old_shares_nullifier,
            self.new_private_shares_commitment,
        ];
        scalars.extend(self.new_public_shares);
        scalars.push(self.merkle_root);
        scalars.extend(self.external_transfer.to_scalars());
        scalars.extend(self.old_pk_root.to_scalars());
        scalars.extend(self.timestamp.to_scalars());
        scalars
    }
}

impl ScalarSerializable for ValidReblindStatement {
    fn to_scalars(&self) -> Vec<ScalarField> {
        vec![
            self.original_shares_nullifier,
            self.reblinded_private_shares_commitment,
            self.merkle_root,
        ]
    }
}

impl ScalarSerializable for ValidCommitmentsStatement {
    fn to_scalars(&self) -> Vec<ScalarField> {
        [
            self.balance_send_index,
            self.balance_receive_index,
            self.order_index,
        ]
        .iter()
        .flat_map(ScalarSerializable::to_scalars)
        .collect()
    }
}

impl ScalarSerializable for ValidMatchSettleStatement {
    fn to_scalars(&self) -> Vec<ScalarField> {
        let mut scalars = Vec::new();
        scalars.extend(self.party0_modified_shares);
        scalars.extend(self.party1_modified_shares);
        scalars.extend(
            [
                self.party0_send_balance_index,
                self.party0_receive_balance_index,
                self.party0_order_index,
                self.party0_send_balance_index,
                self.party0_receive_balance_index,
                self.party0_order_index,
            ]
            .iter()
            .flat_map(ScalarSerializable::to_scalars),
        );
        scalars
    }
}

// ---------------------------
// | GENERIC IMPLEMENTATIONS |
// ---------------------------

impl<S: Serializable> Serializable for &[S] {
    fn serialize(&self) -> Vec<u8> {
        self.iter().flat_map(Serializable::serialize).collect()
    }
}

impl<D: Deserializable, const N: usize> Deserializable for [D; N] {
    const SER_LEN: usize = N * D::SER_LEN;

    fn deserialize(bytes: &[u8]) -> Result<Self, SerdeError> {
        let mut elems = Vec::with_capacity(N);
        let mut offset = 0;
        for _ in 0..N {
            let elem = D::deserialize(&bytes[offset..offset + D::SER_LEN])?;
            elems.push(elem);
            offset += D::SER_LEN;
        }

        elems.try_into().map_err(|_| SerdeError)
    }
}

// -----------
// | HELPERS |
// -----------

fn deserialize_cursor<D: Deserializable>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<D, SerdeError> {
    let elem = D::deserialize(&bytes[*cursor..*cursor + D::SER_LEN])?;
    *cursor += D::SER_LEN;
    Ok(elem)
}

#[cfg(test)]
mod tests {
    use ark_ec::AffineRepr;
    use common::{
        constants::FELT_BYTES,
        types::{G1Affine, G2Affine, Proof, VerificationKey},
    };
    use num_bigint::BigUint;
    use test_helpers::{dummy_proofs, dummy_vkeys};

    use super::{Deserializable, Serializable};

    #[test]
    fn test_g1_precompile_serde() {
        let a = G1Affine::generator();
        let res = a.serialize();
        // EC precompiles return G1 points in the same format, i.e. big-endian serialization of x and y
        // As such we can use this output to test deserialization
        let a_prime = G1Affine::deserialize(&res).unwrap();
        assert_eq!(a, a_prime)
    }

    #[test]
    fn test_g2_precompile_serde() {
        let a = G2Affine::generator();
        let res = a.serialize();

        let x_c1 = BigUint::from_bytes_be(&res[..FELT_BYTES]);
        let x_c0 = BigUint::from_bytes_be(&res[FELT_BYTES..FELT_BYTES * 2]);
        let y_c1 = BigUint::from_bytes_be(&res[FELT_BYTES * 2..FELT_BYTES * 3]);
        let y_c0 = BigUint::from_bytes_be(&res[FELT_BYTES * 3..]);

        // Expected values taken from: https://eips.ethereum.org/EIPS/eip-197#definition-of-the-groups
        assert_eq!(
            x_c1,
            BigUint::parse_bytes(
                b"11559732032986387107991004021392285783925812861821192530917403151452391805634",
                10
            )
            .unwrap()
        );
        assert_eq!(
            x_c0,
            BigUint::parse_bytes(
                b"10857046999023057135944570762232829481370756359578518086990519993285655852781",
                10
            )
            .unwrap()
        );
        assert_eq!(
            y_c1,
            BigUint::parse_bytes(
                b"4082367875863433681332203403145435568316851327593401208105741076214120093531",
                10
            )
            .unwrap()
        );
        assert_eq!(
            y_c0,
            BigUint::parse_bytes(
                b"8495653923123431417604973247489272438418190587263600148770280649306958101930",
                10
            )
            .unwrap()
        );
    }

    #[test]
    fn test_vkey_serde() {
        let vkey = dummy_vkeys(1024, 512).0;
        let vkey_ser = vkey.serialize();
        let vkey_deser = VerificationKey::deserialize(&vkey_ser).unwrap();

        assert_eq!(vkey.n, vkey_deser.n);
        assert_eq!(vkey.l, vkey_deser.l);
        assert_eq!(vkey.k, vkey_deser.k);
        assert_eq!(vkey.q_comms, vkey_deser.q_comms);
        assert_eq!(vkey.sigma_comms, vkey_deser.sigma_comms);
        assert_eq!(vkey.g, vkey_deser.g);
        assert_eq!(vkey.h, vkey_deser.h);
        assert_eq!(vkey.x_h, vkey_deser.x_h);
    }

    #[test]
    fn test_proof_serde() {
        let proof = dummy_proofs().0;
        let proof_ser = proof.serialize();
        let proof_deser = Proof::deserialize(&proof_ser).unwrap();

        assert_eq!(proof.wire_comms, proof_deser.wire_comms);
        assert_eq!(proof.z_comm, proof_deser.z_comm);
        assert_eq!(proof.quotient_comms, proof_deser.quotient_comms);
        assert_eq!(proof.w_zeta, proof_deser.w_zeta);
        assert_eq!(proof.w_zeta_omega, proof_deser.w_zeta_omega);
        assert_eq!(proof.wire_evals, proof_deser.wire_evals);
        assert_eq!(proof.sigma_evals, proof_deser.sigma_evals);
        assert_eq!(proof.z_bar, proof_deser.z_bar);
    }
}
