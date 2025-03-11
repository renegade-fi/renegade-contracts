// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { BN254 } from "solidity-bn254/BN254.sol";
import { BN254Helpers } from "renegade/libraries/verifier/BN254Helpers.sol";
import {
    ExternalTransfer,
    PublicRootKey,
    OrderSettlementIndices,
    ExternalMatchResult,
    FeeTake,
    ElGamalCiphertext,
    EncryptionKey
} from "./Types.sol";

// This file represents the public inputs (statements) for various proofs used by the darkpool

// -------------------
// | Statement Types |
// -------------------

/// @title ValidWalletCreateStatement
/// @notice The statement type for the `VALID WALLET CREATE` proof
struct ValidWalletCreateStatement {
    /// @dev The commitment to the wallet's private shares
    BN254.ScalarField privateShareCommitment;
    /// @dev The public wallet shares of the wallet
    BN254.ScalarField[] publicShares;
}

/// @title ValidWalletUpdateStatement
/// @notice The statement type for the `VALID WALLET UPDATE` proof
struct ValidWalletUpdateStatement {
    /// @dev The nullifier of the previous wallet
    BN254.ScalarField previousNullifier;
    /// @dev A commitment to the new wallet's private shares
    BN254.ScalarField newPrivateShareCommitment;
    /// @dev The new public shares of the wallet
    BN254.ScalarField[] newPublicShares;
    /// @dev The global Merkle root that the old wallet shares open into
    BN254.ScalarField merkleRoot;
    /// @dev The external transfer in the update, zeroed out if there is no transfer
    ExternalTransfer externalTransfer;
    /// @dev The old public root key of the keychain
    PublicRootKey oldPkRoot;
}

/// @title ValidReblindStatement
/// @notice The statement type for the `VALID REBLIND` proof
struct ValidReblindStatement {
    /// @dev The nullifier of the original wallet
    BN254.ScalarField originalSharesNullifier;
    /// @dev A commitment to the new private shares of the reblinded wallet
    BN254.ScalarField newPrivateShareCommitment;
    /// @dev The global Merkle root that the new wallet shares open into
    BN254.ScalarField merkleRoot;
}

/// @title ValidCommitmentsStatement
/// @notice The statement type for the `VALID COMMITMENTS` proof
struct ValidCommitmentsStatement {
    /// @dev The order settlement indices of the party for which this statement is generated
    OrderSettlementIndices indices;
}

/// @title ValidMatchSettleStatement
/// @notice The statement type for the `VALID MATCH SETTLE` proof
struct ValidMatchSettleStatement {
    /// @dev The modified public shares of the first party
    BN254.ScalarField[] firstPartyPublicShares;
    /// @dev The modified public shares of the second party
    BN254.ScalarField[] secondPartyPublicShares;
    /// @dev The settlement indices of the first party
    OrderSettlementIndices firstPartySettlementIndices;
    /// @dev The settlement indices of the second party
    OrderSettlementIndices secondPartySettlementIndices;
    /// @dev The protocol fee rate used for the match
    /// @dev Note that this is a fixed point value encoded as a uint256
    /// @dev so the true fee rate is `protocolFeeRate / 2^{FIXED_POINT_PRECISION}`
    /// @dev Currently, the fixed point precision is 63
    uint256 protocolFeeRate;
}

/// @title ValidMatchSettleAtomicStatement
/// @notice The statement type for the `VALID MATCH SETTLE ATOMIC` proof
struct ValidMatchSettleAtomicStatement {
    /// @dev The result of the match
    ExternalMatchResult matchResult;
    /// @dev The fees due by the external party
    FeeTake externalPartyFees;
    /// @dev The modified public shares of the internal party
    BN254.ScalarField[] internalPartyModifiedShares;
    /// @dev The order settlement indices of the internal party
    OrderSettlementIndices internalPartySettlementIndices;
    /// @dev The protocol fee rate used for the match
    /// @dev This is a fixed point value encoded as a uint256,
    /// @dev see `protocolFeeRate` in `ValidMatchSettleStatement`
    uint256 protocolFeeRate;
    /// @dev The address at which the relayer wishes to receive their fee due
    /// @dev from the external party
    address relayerFeeAddress;
}

/// @title ValidOfflineFeeSettlementStatement
/// @notice The statement type for the `VALID OFFLINE FEE SETTLEMENT` proof
struct ValidOfflineFeeSettlementStatement {
    /// @dev The Merkle root to which inclusion is proven
    BN254.ScalarField merkleRoot;
    /// @dev The nullifier of the wallet paying the fee
    BN254.ScalarField walletNullifier;
    /// @dev The commitment to the payer's updated private shares
    BN254.ScalarField updatedWalletCommitment;
    /// @dev The public shares of the payer's updated wallet
    BN254.ScalarField[] updatedWalletPublicShares;
    /// @dev The ciphertext of the note
    ElGamalCiphertext noteCiphertext;
    /// @dev A commitment to the note
    BN254.ScalarField noteCommitment;
    /// @dev The encryption key of the protocol
    EncryptionKey protocolKey;
    /// @dev Whether or not the fee is paid to the protocol
    bool isProtocolFee;
}

// ------------------------
// | Scalar Serialization |
// ------------------------

/// @title StatementSerializer Library for serializing statement types to scalar arrays
library StatementSerializer {
    using StatementSerializer for ValidWalletCreateStatement;
    using StatementSerializer for ValidWalletUpdateStatement;
    using StatementSerializer for ValidReblindStatement;
    using StatementSerializer for ValidCommitmentsStatement;
    using StatementSerializer for ValidMatchSettleStatement;
    using StatementSerializer for ValidMatchSettleAtomicStatement;
    using StatementSerializer for ValidOfflineFeeSettlementStatement;
    using StatementSerializer for ExternalTransfer;
    using StatementSerializer for PublicRootKey;
    using StatementSerializer for OrderSettlementIndices;
    using StatementSerializer for ExternalMatchResult;
    using StatementSerializer for FeeTake;
    using StatementSerializer for ElGamalCiphertext;
    using StatementSerializer for EncryptionKey;
    /// @notice The number of scalar field elements in a ValidWalletCreateStatement

    uint256 constant VALID_WALLET_CREATE_SCALAR_SIZE = 71;
    /// @notice The number of scalar field elements in a ValidWalletUpdateStatement
    uint256 constant VALID_WALLET_UPDATE_SCALAR_SIZE = 81;
    /// @notice The number of scalar field elements in a ValidReblindStatement
    uint256 constant VALID_REBLIND_SCALAR_SIZE = 3;
    /// @notice The number of scalar field elements in a ValidCommitmentsStatement
    uint256 constant VALID_COMMITMENTS_SCALAR_SIZE = 3;
    /// @notice The number of scalar field elements in a ValidMatchSettleStatement
    uint256 constant VALID_MATCH_SETTLE_SCALAR_SIZE = 147;
    /// @notice The number of scalar field elements in a ValidMatchSettleAtomicStatement
    uint256 constant VALID_MATCH_SETTLE_ATOMIC_SCALAR_SIZE = 82;
    /// @notice The number of scalar field elements in a ValidOfflineFeeSettlementStatement
    uint256 constant VALID_OFFLINE_FEE_SETTLEMENT_SCALAR_SIZE = 82;

    // --- Valid Wallet Create --- //

    /// @notice Serializes a ValidWalletCreateStatement into an array of scalar field elements
    /// @param self The statement to serialize
    /// @return serialized The serialized statement as an array of scalar field elements
    function scalarSerialize(ValidWalletCreateStatement memory self)
        internal
        pure
        returns (BN254.ScalarField[] memory)
    {
        // Create array with size = 1 (for privateShareCommitment) + publicShares.length
        BN254.ScalarField[] memory serialized = new BN254.ScalarField[](VALID_WALLET_CREATE_SCALAR_SIZE);

        // Add the wallet commitment
        serialized[0] = self.privateShareCommitment;

        // Add all public shares
        for (uint256 i = 0; i < self.publicShares.length; i++) {
            serialized[i + 1] = self.publicShares[i];
        }

        return serialized;
    }

    // --- Valid Wallet Update --- //

    /// @notice Serializes a ValidWalletUpdateStatement into an array of scalar field elements
    /// @param self The statement to serialize
    /// @return serialized The serialized statement as an array of scalar field elements
    function scalarSerialize(ValidWalletUpdateStatement memory self)
        internal
        pure
        returns (BN254.ScalarField[] memory)
    {
        BN254.ScalarField[] memory serialized = new BN254.ScalarField[](VALID_WALLET_UPDATE_SCALAR_SIZE);
        serialized[0] = self.previousNullifier;
        serialized[1] = self.newPrivateShareCommitment;

        // Copy the public shares
        uint256 n = self.newPublicShares.length;
        for (uint256 i = 0; i < n; i++) {
            serialized[i + 2] = self.newPublicShares[i];
        }

        serialized[n + 2] = self.merkleRoot;
        BN254.ScalarField[] memory externalTransferSerialized = self.externalTransfer.scalarSerialize();
        for (uint256 i = 0; i < externalTransferSerialized.length; i++) {
            serialized[n + 3 + i] = externalTransferSerialized[i];
        }

        BN254.ScalarField[] memory oldPkRootSerialized = self.oldPkRoot.scalarSerialize();
        for (uint256 i = 0; i < oldPkRootSerialized.length; i++) {
            serialized[n + 3 + externalTransferSerialized.length + i] = oldPkRootSerialized[i];
        }

        return serialized;
    }

    // --- Valid Reblind --- //

    /// @notice Serializes a ValidReblindStatement into an array of scalar field elements
    /// @param self The statement to serialize
    /// @return serialized The serialized statement as an array of scalar field elements
    function scalarSerialize(ValidReblindStatement memory self) internal pure returns (BN254.ScalarField[] memory) {
        BN254.ScalarField[] memory serialized = new BN254.ScalarField[](VALID_REBLIND_SCALAR_SIZE);
        serialized[0] = self.originalSharesNullifier;
        serialized[1] = self.newPrivateShareCommitment;
        serialized[2] = self.merkleRoot;

        return serialized;
    }

    // --- Valid Commitments --- //

    /// @notice Serializes a ValidCommitmentsStatement into an array of scalar field elements
    /// @param self The statement to serialize
    /// @return serialized The serialized statement as an array of scalar field elements
    function scalarSerialize(ValidCommitmentsStatement memory self)
        internal
        pure
        returns (BN254.ScalarField[] memory)
    {
        BN254.ScalarField[] memory serialized = new BN254.ScalarField[](VALID_COMMITMENTS_SCALAR_SIZE);
        serialized[0] = BN254.ScalarField.wrap(self.indices.balanceSend);
        serialized[1] = BN254.ScalarField.wrap(self.indices.balanceReceive);
        serialized[2] = BN254.ScalarField.wrap(self.indices.order);

        return serialized;
    }

    // --- Valid Match Settle --- //

    /// @notice Serializes a ValidMatchSettleStatement into an array of scalar field elements
    /// @param self The statement to serialize
    /// @return serialized The serialized statement as an array of scalar field elements
    function scalarSerialize(ValidMatchSettleStatement memory self)
        internal
        pure
        returns (BN254.ScalarField[] memory)
    {
        BN254.ScalarField[] memory serialized = new BN254.ScalarField[](VALID_MATCH_SETTLE_SCALAR_SIZE);

        // Copy the public shares
        uint256 n = self.firstPartyPublicShares.length;
        for (uint256 i = 0; i < n; i++) {
            serialized[i] = self.firstPartyPublicShares[i];
        }

        // Copy the second party public shares
        uint256 offset = self.firstPartyPublicShares.length;
        for (uint256 i = 0; i < n; i++) {
            serialized[offset + i] = self.secondPartyPublicShares[i];
        }

        // Copy the settlement indices
        offset += n;
        BN254.ScalarField[] memory firstPartySettlementIndicesSerialized =
            self.firstPartySettlementIndices.scalarSerialize();
        for (uint256 i = 0; i < firstPartySettlementIndicesSerialized.length; i++) {
            serialized[offset + i] = firstPartySettlementIndicesSerialized[i];
        }

        // Copy the second party settlement indices
        offset += firstPartySettlementIndicesSerialized.length;
        BN254.ScalarField[] memory secondPartySettlementIndicesSerialized =
            self.secondPartySettlementIndices.scalarSerialize();
        for (uint256 i = 0; i < secondPartySettlementIndicesSerialized.length; i++) {
            serialized[offset + i] = secondPartySettlementIndicesSerialized[i];
        }

        // Copy the protocol fee rate
        serialized[serialized.length - 1] = BN254.ScalarField.wrap(self.protocolFeeRate);
        return serialized;
    }

    // --- Valid Match Settle Atomic --- //

    /// @notice Serializes a ValidMatchSettleAtomicStatement into an array of scalar field elements
    /// @param self The statement to serialize
    /// @return serialized The serialized statement as an array of scalar field elements
    function scalarSerialize(ValidMatchSettleAtomicStatement memory self)
        internal
        pure
        returns (BN254.ScalarField[] memory)
    {
        BN254.ScalarField[] memory serialized = new BN254.ScalarField[](VALID_MATCH_SETTLE_ATOMIC_SCALAR_SIZE);

        // Copy the match result
        BN254.ScalarField[] memory matchResultSerialized = self.matchResult.scalarSerialize();
        for (uint256 i = 0; i < matchResultSerialized.length; i++) {
            serialized[i] = matchResultSerialized[i];
        }

        // Copy the external party fees
        uint256 offset = matchResultSerialized.length;
        BN254.ScalarField[] memory externalPartyFeesSerialized = self.externalPartyFees.scalarSerialize();
        for (uint256 i = 0; i < externalPartyFeesSerialized.length; i++) {
            serialized[offset + i] = externalPartyFeesSerialized[i];
        }

        // Copy the internal party modified shares
        offset += externalPartyFeesSerialized.length;
        for (uint256 i = 0; i < self.internalPartyModifiedShares.length; i++) {
            serialized[offset + i] = self.internalPartyModifiedShares[i];
        }

        // Copy the internal party settlement indices
        offset += self.internalPartyModifiedShares.length;
        BN254.ScalarField[] memory internalPartySettlementIndicesSerialized =
            self.internalPartySettlementIndices.scalarSerialize();
        for (uint256 i = 0; i < internalPartySettlementIndicesSerialized.length; i++) {
            serialized[offset + i] = internalPartySettlementIndicesSerialized[i];
        }

        // Copy the protocol fee rate and relayer fee address
        serialized[serialized.length - 2] = BN254.ScalarField.wrap(self.protocolFeeRate);
        serialized[serialized.length - 1] = BN254.ScalarField.wrap(uint256(uint160(self.relayerFeeAddress)));
        return serialized;
    }

    // --- Valid Offline Fee Settlement --- //

    /// @notice Serializes a ValidOfflineFeeSettlementStatement into an array of scalar field elements
    /// @param self The statement to serialize
    /// @return serialized The serialized statement as an array of scalar field elements
    function scalarSerialize(ValidOfflineFeeSettlementStatement memory self)
        internal
        pure
        returns (BN254.ScalarField[] memory)
    {
        BN254.ScalarField[] memory serialized = new BN254.ScalarField[](VALID_OFFLINE_FEE_SETTLEMENT_SCALAR_SIZE);
        serialized[0] = self.merkleRoot;
        serialized[1] = self.walletNullifier;
        serialized[2] = self.updatedWalletCommitment;

        // Serialize the updated wallet public shares
        uint256 offset = 3;
        for (uint256 i = 0; i < self.updatedWalletPublicShares.length; i++) {
            serialized[offset + i] = self.updatedWalletPublicShares[i];
        }
        offset += self.updatedWalletPublicShares.length;

        // Serialize the note ciphertext
        BN254.ScalarField[] memory noteCiphertextSerialized = self.noteCiphertext.scalarSerialize();
        for (uint256 i = 0; i < noteCiphertextSerialized.length; i++) {
            serialized[offset + i] = noteCiphertextSerialized[i];
        }
        offset += noteCiphertextSerialized.length;

        // Serialize the note commitment
        serialized[offset] = self.noteCommitment;
        offset += 1;

        // Serialize the protocol key
        BN254.ScalarField[] memory protocolKeySerialized = self.protocolKey.scalarSerialize();
        for (uint256 i = 0; i < protocolKeySerialized.length; i++) {
            serialized[offset + i] = protocolKeySerialized[i];
        }
        offset += protocolKeySerialized.length;

        // Serialize the is protocol fee flag
        serialized[offset] = self.isProtocolFee ? BN254Helpers.ONE : BN254Helpers.ZERO;
        return serialized;
    }

    // --- Types --- //

    /// @notice Serializes an ExternalTransfer into an array of scalar field elements
    /// @param self The transfer to serialize
    /// @return serialized The serialized transfer as an array of scalar field elements
    function scalarSerialize(ExternalTransfer memory self) internal pure returns (BN254.ScalarField[] memory) {
        BN254.ScalarField[] memory serialized = new BN254.ScalarField[](4);

        serialized[0] = BN254.ScalarField.wrap(uint256(uint160(self.account)));
        serialized[1] = BN254.ScalarField.wrap(uint256(uint160(self.mint)));
        serialized[2] = BN254.ScalarField.wrap(self.amount);
        serialized[3] = BN254.ScalarField.wrap(uint256(self.transferType));

        return serialized;
    }

    /// @notice Serializes a PublicRootKey into an array of scalar field elements
    /// @param self The key to serialize
    /// @return serialized The serialized key as an array of scalar field elements
    function scalarSerialize(PublicRootKey memory self) internal pure returns (BN254.ScalarField[] memory) {
        BN254.ScalarField[] memory serialized = new BN254.ScalarField[](4);

        serialized[0] = self.x[0];
        serialized[1] = self.x[1];
        serialized[2] = self.y[0];
        serialized[3] = self.y[1];

        return serialized;
    }

    /// @notice Serializes an OrderSettlementIndices into an array of scalar field elements
    /// @param self The indices to serialize
    /// @return serialized The serialized indices as an array of scalar field elements
    function scalarSerialize(OrderSettlementIndices memory self) internal pure returns (BN254.ScalarField[] memory) {
        BN254.ScalarField[] memory serialized = new BN254.ScalarField[](3);

        serialized[0] = BN254.ScalarField.wrap(self.balanceSend);
        serialized[1] = BN254.ScalarField.wrap(self.balanceReceive);
        serialized[2] = BN254.ScalarField.wrap(self.order);

        return serialized;
    }

    /// @notice Serializes an ExternalMatchResult into an array of scalar field elements
    /// @param self The result to serialize
    /// @return serialized The serialized result as an array of scalar field elements
    function scalarSerialize(ExternalMatchResult memory self) internal pure returns (BN254.ScalarField[] memory) {
        BN254.ScalarField[] memory serialized = new BN254.ScalarField[](5);
        serialized[0] = BN254.ScalarField.wrap(uint256(uint160(self.quoteMint)));
        serialized[1] = BN254.ScalarField.wrap(uint256(uint160(self.baseMint)));
        serialized[2] = BN254.ScalarField.wrap(self.quoteAmount);
        serialized[3] = BN254.ScalarField.wrap(self.baseAmount);
        serialized[4] = BN254.ScalarField.wrap(uint256(self.direction));

        return serialized;
    }

    /// @notice Serializes a FeeTake into an array of scalar field elements
    /// @param self The fee take to serialize
    /// @return serialized The serialized fee take as an array of scalar field elements
    function scalarSerialize(FeeTake memory self) internal pure returns (BN254.ScalarField[] memory) {
        BN254.ScalarField[] memory serialized = new BN254.ScalarField[](2);
        serialized[0] = BN254.ScalarField.wrap(self.relayerFee);
        serialized[1] = BN254.ScalarField.wrap(self.protocolFee);

        return serialized;
    }

    /// @notice Serializes an ElGamalCiphertext into an array of scalar field elements
    /// @param self The ciphertext to serialize
    /// @return serialized The serialized ciphertext as an array of scalar field elements
    function scalarSerialize(ElGamalCiphertext memory self) internal pure returns (BN254.ScalarField[] memory) {
        BN254.ScalarField[] memory serialized = new BN254.ScalarField[](2 + self.ciphertext.length);
        serialized[0] = self.ephemeralKey.x;
        serialized[1] = self.ephemeralKey.y;

        for (uint256 i = 0; i < self.ciphertext.length; i++) {
            serialized[2 + i] = self.ciphertext[i];
        }
        return serialized;
    }

    /// @notice Serializes an EncryptionKey into an array of scalar field elements
    /// @param self The key to serialize
    /// @return serialized The serialized key as an array of scalar field elements
    function scalarSerialize(EncryptionKey memory self) internal pure returns (BN254.ScalarField[] memory) {
        BN254.ScalarField[] memory serialized = new BN254.ScalarField[](2);
        serialized[0] = self.point.x;
        serialized[1] = self.point.y;

        return serialized;
    }
}
