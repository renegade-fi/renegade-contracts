// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

// This file contains the types used in the darkpool

import { BN254 } from "solidity-bn254/BN254.sol";
import { ValidCommitmentsStatement, ValidReblindStatement } from "./PublicInputs.sol";
import { PlonkProof, LinkingProof } from "../verifier/Types.sol";

/// @dev The type hash for the DepositWitness struct
bytes32 constant DEPOSIT_WITNESS_TYPEHASH = keccak256("DepositWitness(uint256[4] pkRoot)");
/// @dev The type string for the DepositWitness struct
/// @dev We must include the `TokenPermission` type encoding as well as this is concatenated with
/// @dev the `PermitWitnessTransferFrom` type encoding stub of the form:
/// @dev `PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,`
/// @dev So we must prepare our type string to concatenate to the entire type encoding
/// @dev See:
/// https://github.com/Uniswap/permit2/blob/cc56ad0f3439c502c246fc5cfcc3db92bb8b7219/src/libraries/PermitHash.sol#L31-L32
string constant DEPOSIT_WITNESS_TYPE_STRING =
    "DepositWitness witness)DepositWitness(uint256[4] pkRoot)TokenPermissions(address token,uint256 amount)";

// ---------------------
// | External Transfer |
// ---------------------

/// @notice An external transfer representing a deposit or withdrawal into/from the darkpool
struct ExternalTransfer {
    /// @dev The account address of the sender/recipient
    address account;
    /// @dev The mint (erc20 address) of the token
    address mint;
    /// @dev The amount of the transfer
    uint256 amount;
    /// @dev Indicates if it's a deposit or withdrawal
    TransferType transferType;
}

/// @notice The type of transfer
enum TransferType {
    Deposit,
    Withdrawal
}

/// @notice Auxiliary data authorizing a transfer
/// @dev This struct is effectively a union of the auth required for
/// @dev a deposit (permit2) and that required for a withdrawal (a simple signature)
/// @dev The external transfer implementation will use the appropriate authorization
/// @dev based on the transfer type
struct TransferAuthorization {
    /// @dev The nonce of the permit
    uint256 permit2Nonce;
    /// @dev The deadline of the permit
    uint256 permit2Deadline;
    /// @dev The signature of the permit
    bytes permit2Signature;
    /// @dev The signature of the external transfer
    bytes externalTransferSignature;
}

/// @notice The permit2 witness for a deposit
/// @dev The Permit2 witness type used in a deposit
struct DepositWitness {
    /// @dev The limb-serialization of the public key of the old wallet
    uint256[4] pkRoot;
}

// -------------
// | Fee Types |
// -------------

/// @title FeeTake
/// @notice The fees due by a party in a match
struct FeeTake {
    /// @dev The fee due to the relayer
    uint256 relayerFee;
    /// @dev The fee due to the protocol
    uint256 protocolFee;
}

/// @title

// --------------------
// | Settlement Types |
// --------------------

/// @title ExternalMatchResult
/// @notice The result of a match between an internal and external party
struct ExternalMatchResult {
    /// @dev The quote mint of the match
    address quoteMint;
    /// @dev The base mint of the match
    address baseMint;
    /// @dev The amount of the match
    uint256 quoteAmount;
    /// @dev The amount of the match
    uint256 baseAmount;
    /// @dev The direction of the match
    ExternalMatchDirection direction;
}

/// @title ExternalMatchDirection
/// @notice The direction of a match between an internal and external party
enum ExternalMatchDirection {
    /// @dev The internal party buys the base and sells the quote
    InternalPartyBuy,
    /// @dev The internal party sells the base and buys the quote
    InternalPartySell
}

/// @title PartyMatchPayload
/// @notice Contains the statement types for a single party's validity proofs in a match
struct PartyMatchPayload {
    /// @dev The statement types for the `VALID COMMITMENTS` proof
    ValidCommitmentsStatement validCommitmentsStatement;
    /// @dev The statement types for the `VALID REBLIND` proof
    ValidReblindStatement validReblindStatement;
}

/// @title MatchProofs
/// @notice Contains the proofs for a match between two parties in the darkpool
/// @dev This contains the validity proofs for the two parties and a proof of
/// @dev `VALID MATCH SETTLE` for settlement
struct MatchProofs {
    /// @dev The first party's proof of `VALID COMMITMENTS`
    PlonkProof validCommitments0;
    /// @dev The first party's proof of `VALID REBLIND`
    PlonkProof validReblind0;
    /// @dev The second party's proof of `VALID COMMITMENTS`
    PlonkProof validCommitments1;
    /// @dev The second party's proof of `VALID REBLIND`
    PlonkProof validReblind1;
    /// @dev The proof of `VALID MATCH SETTLE`
    PlonkProof validMatchSettle;
}

/// @title MatchLinkingProofs
/// @notice Contains the proof linking arguments for a match
/// @dev This contains four proofs: two linking the internal party's `VALID REBLIND`
/// @dev to their `VALID COMMITMENTS`, and two linking the internal party's
/// @dev `VALID COMMITMENTS` to the proof of `VALID MATCH SETTLE`
struct MatchLinkingProofs {
    /// @dev The proof of linked inputs between PARTY 0 VALID REBLIND <-> PARTY 0 VALID COMMITMENTS
    LinkingProof validReblindCommitments0;
    /// @dev The proof of linked inputs between PARTY 0 VALID COMMITMENTS <-> VALID MATCH SETTLE
    LinkingProof validCommitmentsMatchSettle0;
    /// @dev The proof of linked inputs between PARTY 1 VALID REBLIND <-> PARTY 1 VALID COMMITMENTS
    LinkingProof validReblindCommitments1;
    /// @dev The proof of linked inputs between PARTY 1 VALID COMMITMENTS <-> VALID MATCH SETTLE
    LinkingProof validCommitmentsMatchSettle1;
}

/// @title MatchAtomicProofs
/// @notice Contains the proofs for a match between two parties in the darkpool
/// @dev This contains the validity proofs for the internal party and a proof of
/// @dev `VALID MATCH SETTLE ATOMIC` for settlement
struct MatchAtomicProofs {
    /// @dev The proof of `VALID COMMITMENTS` for the internal party
    PlonkProof validCommitments;
    /// @dev The proof of `VALID REBLIND` for the internal party
    PlonkProof validReblind;
    /// @dev The proof of `VALID MATCH SETTLE ATOMIC`
    PlonkProof validMatchSettleAtomic;
}

/// @title MatchAtomicLinkingProofs
/// @notice Contains the proof linking arguments for a match
/// @dev This contains one proof that links the internal party's `VALID REBLIND`
/// @dev to their `VALID COMMITMENTS`, and another that links the internal party's
/// @dev `VALID COMMITMENTS` to the proof of `VALID MATCH SETTLE ATOMIC`
struct MatchAtomicLinkingProofs {
    /// @dev The proof of linked inputs between PARTY 0 VALID REBLIND <-> PARTY 0 VALID COMMITMENTS
    LinkingProof validReblindCommitments;
    /// @dev The proof of linked inputs between PARTY 0 VALID COMMITMENTS <-> VALID MATCH SETTLE ATOMIC
    LinkingProof validCommitmentsMatchSettleAtomic;
}

/// @notice A set of indices into a settlement party's wallet for the receive balance
struct OrderSettlementIndices {
    /// @dev The index of the balance holding the mint which teh wallet will
    /// @dev sell in a match
    uint256 balanceSend;
    /// @dev The index of the balance holding the mint which the wallet will
    /// @dev buy in a match
    uint256 balanceReceive;
    /// @dev the index of the order that is matched in the wallet
    uint256 order;
}

// ------------
// | Keychain |
// ------------

/// @notice A public root key, essentially a `Scalar` representation of a k256 public key
/// @dev The `x` and `y` coordinates are elements of the base field of the k256 curve, which
/// @dev each require 254 bits to represent
struct PublicRootKey {
    /// @dev The x coordinate of the public key
    BN254.ScalarField[2] x;
    /// @dev The y coordinate of the public key
    BN254.ScalarField[2] y;
}

/// @notice Serialize the public root key into a list of uint256s
function publicKeyToUints(PublicRootKey memory pk) pure returns (uint256[4] memory scalars) {
    scalars[0] = BN254.ScalarField.unwrap(pk.x[0]);
    scalars[1] = BN254.ScalarField.unwrap(pk.x[1]);
    scalars[2] = BN254.ScalarField.unwrap(pk.y[0]);
    scalars[3] = BN254.ScalarField.unwrap(pk.y[1]);
}

// --------------
// | Ciphertext |
// --------------

/// @title ElGamalCiphertext
/// @notice A ciphertext of an ElGamal hybrid encryption
/// @dev The ciphertext consists of an asymmetric ephemeral key -- a random point on an elliptic curve (see below) --
/// @dev and a series of field elements in the base field of the curve.
/// @dev The encryption of the plaintext multiplies the public key with a random scalar, generating the ephemeral key.
/// @dev The ephemeral key's x and y coordinates seed a cipher which is used to encrypt the plaintext in a symmetric
/// stream.
/// @dev The ciphertext thus consists of:
///     - the random scalar multiplied with the curve basepoint, so that the decryption may recover the ephemeral key
///     - the stream-encrypted plaintext
/// @dev For our system, we encrypt over the Baby JubJub curve, which has a base field isomorphic to the scalar
/// @dev field of the BN254 elliptic curve, over which we construct our proofs. This gives a particularly efficient
/// @dev cipher, using proof-system-native arithmetic.
struct ElGamalCiphertext {
    /// @dev The ephemeral key
    BabyJubJubPoint ephemeralKey;
    /// @dev The ciphertext
    BN254.ScalarField[] ciphertext;
}

/// @title BabyJubJubPoint
/// @notice A point on the Baby JubJub curve
struct BabyJubJubPoint {
    /// @dev The x coordinate of the point
    BN254.ScalarField x;
    /// @dev The y coordinate of the point
    BN254.ScalarField y;
}

/// @title EncryptionKey
/// @notice A public key for the above ElGamal hybrid cryptosystem
struct EncryptionKey {
    /// @dev The underlying point on the Baby JubJub curve
    BabyJubJubPoint point;
}

// ------------------
// | Helper Library |
// ------------------

/// @title TypesLib
/// @notice A library that allows us to define function on types in the darkpool
library TypesLib {
    // --- External Transfers --- //

    /// @notice Checks if an ExternalTransfer has zero values
    /// @param transfer The ExternalTransfer to check
    /// @return True if the amount is zero
    function isZero(ExternalTransfer memory transfer) public pure returns (bool) {
        return transfer.amount == 0;
    }

    /// @notice Computes the EIP-712 hash of a DepositWitness
    /// @param witness The DepositWitness to hash
    /// @return The EIP-712 hash of the DepositWitness
    function hashWitness(DepositWitness memory witness) public pure returns (bytes32) {
        // Hash the struct data according to EIP-712
        bytes32 pkRootHash = keccak256(abi.encode(witness.pkRoot));
        return keccak256(abi.encode(DEPOSIT_WITNESS_TYPEHASH, pkRootHash));
    }

    // --- Order Settlement Indices --- //

    /// @notice Return whether two sets of indices are equal
    /// @param a The first set of indices
    /// @param b The second set of indices
    /// @return True if the indices are equal, false otherwise
    function indicesEqual(
        OrderSettlementIndices memory a,
        OrderSettlementIndices memory b
    )
        public
        pure
        returns (bool)
    {
        return a.balanceSend == b.balanceSend && a.balanceReceive == b.balanceReceive && a.order == b.order;
    }

    // --- Match Settlement --- //

    /// @notice Return the sell mint and amount for the external party
    function externalPartySellMintAmount(ExternalMatchResult memory matchResult)
        public
        pure
        returns (address, uint256)
    {
        if (matchResult.direction == ExternalMatchDirection.InternalPartyBuy) {
            return (matchResult.baseMint, matchResult.baseAmount);
        } else {
            return (matchResult.quoteMint, matchResult.quoteAmount);
        }
    }

    /// @notice Return the buy mint and amount for the external party
    function externalPartyBuyMintAmount(ExternalMatchResult memory matchResult)
        public
        pure
        returns (address, uint256)
    {
        if (matchResult.direction == ExternalMatchDirection.InternalPartyBuy) {
            return (matchResult.quoteMint, matchResult.quoteAmount);
        } else {
            return (matchResult.baseMint, matchResult.baseAmount);
        }
    }

    // --- Fees --- //

    /// @notice Return the total fees due on a fee take
    /// @param feeTake The fee take to compute the total fees for
    /// @return The total fees due
    function total(FeeTake memory feeTake) public pure returns (uint256) {
        return feeTake.relayerFee + feeTake.protocolFee;
    }

    // --- Encryption --- //

    /// @notice Check whether two encryption keys are equal
    /// @param a The first encryption key
    /// @param b The second encryption key
    /// @return Whether the keys are equal
    function encryptionKeyEqual(EncryptionKey memory a, EncryptionKey memory b) public pure returns (bool) {
        bool xEqual = BN254.ScalarField.unwrap(a.point.x) == BN254.ScalarField.unwrap(b.point.x);
        bool yEqual = BN254.ScalarField.unwrap(a.point.y) == BN254.ScalarField.unwrap(b.point.y);
        return xEqual && yEqual;
    }
}
