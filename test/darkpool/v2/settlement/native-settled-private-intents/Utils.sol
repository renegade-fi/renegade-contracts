// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import { BN254 } from "solidity-bn254/BN254.sol";
import { DarkpoolV2TestUtils } from "../../DarkpoolV2TestUtils.sol";
import { SettlementObligation } from "darkpoolv2-types/Obligation.sol";
import {
    SettlementBundle,
    SettlementBundleType,
    PrivateIntentPublicBalanceBundle
} from "darkpoolv2-types/settlement/SettlementBundle.sol";
import { ObligationBundle, ObligationType, ObligationLib } from "darkpoolv2-types/settlement/ObligationBundle.sol";
import { PrivateIntentAuthBundle } from "darkpoolv2-types/settlement/IntentBundle.sol";
import { SettlementContext, SettlementContextLib } from "darkpoolv2-types/settlement/SettlementContext.sol";
import { FixedPoint, FixedPointLib } from "renegade-lib/FixedPoint.sol";
import { DarkpoolConstants } from "darkpoolv2-lib/Constants.sol";
import { IntentOnlyValidityStatement, SingleIntentMatchSettlementStatement } from "darkpoolv2-lib/PublicInputs.sol";
import { EfficientHashLib } from "solady/utils/EfficientHashLib.sol";
import { CommitmentNullifierLib } from "darkpoolv2-types/CommitNullify.sol";

contract PrivateIntentSettlementTestUtils is DarkpoolV2TestUtils {
    using ObligationLib for ObligationBundle;
    using FixedPointLib for FixedPoint;

    // ---------
    // | Utils |
    // ---------

    // --- Signatures --- //

    /// @dev Sign an intent commitment
    function signIntentCommitment(
        BN254.ScalarField intentCommitment,
        uint256 signerPrivateKey
    )
        internal
        pure
        returns (bytes memory)
    {
        // Hash the intent commitment
        bytes32 intentCommitmentBytes = bytes32(BN254.ScalarField.unwrap(intentCommitment));
        bytes32 commitmentHash = EfficientHashLib.hash(abi.encode(intentCommitmentBytes));

        // Sign with the private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, commitmentHash);
        return abi.encodePacked(r, s, v);
    }

    // --- Dummy Data --- //

    /// @dev Create a dummy `SettlementContext` for the test
    function _createSettlementContext() internal pure returns (SettlementContext memory context) {
        context = SettlementContextLib.newContext(2, /* transferCapacity */ 2 /* verificationCapacity */ );
    }

    /// @dev Create a dummy intent validity statement
    function createSampleIntentValidityStatement(SettlementObligation memory obligation)
        internal
        returns (IntentOnlyValidityStatement memory)
    {
        return IntentOnlyValidityStatement({
            intentOwner: intentOwner.addr,
            newIntentPartialCommitment: randomScalar(),
            nullifier: randomScalar(),
            obligation: obligation
        });
    }

    /// @dev Create a dummy settlement statement
    function createSampleSettlementStatement() internal returns (SingleIntentMatchSettlementStatement memory) {
        return SingleIntentMatchSettlementStatement({ newIntentAmountPublicShare: randomScalar() });
    }

    /// @dev Helper to create a sample settlement bundle
    function createSampleBundle() internal returns (SettlementBundle memory) {
        // Create obligation
        SettlementObligation memory obligation = SettlementObligation({
            inputToken: address(baseToken),
            outputToken: address(quoteToken),
            amountIn: 100,
            amountOut: 200
        });

        return createSettlementBundle(obligation, intentOwner.addr);
    }

    /// @dev Create a complete settlement bundle given an obligation
    function createSettlementBundle(
        SettlementObligation memory obligation,
        address owner
    )
        internal
        returns (SettlementBundle memory)
    {
        return createSettlementBundleWithSigner(
            obligation,
            owner,
            intentOwner.privateKey,
            true, // isFirstFill
            DarkpoolConstants.DEFAULT_MERKLE_DEPTH
        );
    }

    /// @dev Create a complete settlement bundle with custom signer and parameters
    function createSettlementBundleWithSigner(
        SettlementObligation memory obligation,
        address owner,
        uint256 ownerPrivateKey,
        bool isFirstFill,
        uint256 merkleDepth
    )
        internal
        returns (SettlementBundle memory)
    {
        // Create validity statement
        IntentOnlyValidityStatement memory validityStatement = IntentOnlyValidityStatement({
            intentOwner: owner,
            newIntentPartialCommitment: randomScalar(),
            nullifier: randomScalar(),
            obligation: obligation
        });

        // Create settlement statement
        SingleIntentMatchSettlementStatement memory settlementStatement = createSampleSettlementStatement();

        // Compute the full intent commitment and sign it
        BN254.ScalarField fullCommitment = computeFullIntentCommitment(
            validityStatement.newIntentPartialCommitment, settlementStatement.newIntentAmountPublicShare
        );
        bytes memory intentSignature = signIntentCommitment(fullCommitment, ownerPrivateKey);

        // Create auth bundle
        PrivateIntentAuthBundle memory auth = PrivateIntentAuthBundle({
            isFirstFill: isFirstFill,
            intentSignature: intentSignature,
            merkleDepth: merkleDepth,
            statement: validityStatement,
            validityProof: createDummyProof()
        });
        PrivateIntentPublicBalanceBundle memory bundleData = PrivateIntentPublicBalanceBundle({
            auth: auth,
            settlementStatement: settlementStatement,
            settlementProof: createDummyProof()
        });

        // Create and encode the obligation bundle
        ObligationBundle memory obligationBundle =
            ObligationBundle({ obligationType: ObligationType.PUBLIC, data: abi.encode(obligation) });
        return SettlementBundle({
            obligation: obligationBundle,
            bundleType: SettlementBundleType.NATIVELY_SETTLED_PRIVATE_INTENT,
            data: abi.encode(bundleData)
        });
    }

    // --- Commitment Computation --- //

    /// @dev Compute the full intent commitment from partial commitment and public share
    function computeFullIntentCommitment(
        BN254.ScalarField partialCommitment,
        BN254.ScalarField amountPublicShare
    )
        internal
        view
        returns (BN254.ScalarField)
    {
        BN254.ScalarField[] memory remainingShares = new BN254.ScalarField[](1);
        remainingShares[0] = amountPublicShare;
        return CommitmentNullifierLib.computeFullCommitment(partialCommitment, remainingShares, hasher);
    }
}
