// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { Initializable } from "oz-contracts/proxy/utils/Initializable.sol";
import { Ownable } from "oz-contracts/access/Ownable.sol";
import { Ownable2Step } from "oz-contracts/access/Ownable2Step.sol";
import { Pausable } from "oz-contracts/utils/Pausable.sol";
import { IPermit2 } from "permit2-lib/interfaces/IPermit2.sol";

import { IHasher } from "renegade-lib/interfaces/IHasher.sol";
import { IDarkpoolV2 } from "darkpoolv2-interfaces/IDarkpoolV2.sol";
import { IVerifier } from "darkpoolv2-interfaces/IVerifier.sol";
import { IWETH9 } from "renegade-lib/interfaces/IWETH9.sol";

import { BN254 } from "solidity-bn254/BN254.sol";

import { MerkleMountainLib } from "renegade-lib/merkle/MerkleMountain.sol";
import { NullifierLib } from "renegade-lib/NullifierSet.sol";

import { EncryptionKey } from "darkpoolv1-types/Ciphertext.sol";

import { ObligationBundle } from "darkpoolv2-types/settlement/ObligationBundle.sol";
import { PartyId, SettlementBundle } from "darkpoolv2-types/settlement/SettlementBundle.sol";
import { SettlementContext } from "darkpoolv2-types/settlement/SettlementContext.sol";
import { DepositProofBundle } from "darkpoolv2-types/ProofBundles.sol";
import { Deposit, DepositAuth } from "darkpoolv2-types/transfers/Deposit.sol";
import { SettlementLib } from "darkpoolv2-lib/settlement/SettlementLib.sol";
import { DarkpoolState, DarkpoolStateLib } from "darkpoolv2-lib/DarkpoolState.sol";
import { ExternalTransferLib as TransferLib } from "darkpoolv2-lib/TransferLib.sol";

/// @title DarkpoolV2
/// @author Renegade Eng
/// @notice V2 of the Renegade darkpool contract for private trading
contract DarkpoolV2 is Initializable, Ownable2Step, Pausable, IDarkpoolV2 {
    using MerkleMountainLib for MerkleMountainLib.MerkleMountainRange;
    using NullifierLib for NullifierLib.NullifierSet;
    using DarkpoolStateLib for DarkpoolState;

    // ----------
    // | Errors |
    // ----------

    /// @notice Thrown when a deposit verification fails
    error DepositVerificationFailed();

    // ----------
    // | Events |
    // ----------

    /// @notice Emitted when the protocol fee rate is changed
    /// @param newFee The new protocol fee rate
    event FeeChanged(uint256 indexed newFee);
    /// @notice Emitted when a per-token fee override is changed
    /// @param asset The asset address
    /// @param newFee The new fee rate for the asset
    event ExternalMatchFeeChanged(address indexed asset, uint256 indexed newFee);
    /// @notice Emitted when the protocol's public key is rotated
    /// @param newPubkeyX The x-coordinate of the new public key
    /// @param newPubkeyY The y-coordinate of the new public key
    event PubkeyRotated(uint256 indexed newPubkeyX, uint256 indexed newPubkeyY);
    /// @notice Emitted when the external fee collection address is changed
    /// @param newAddress The new fee collection address
    event ExternalFeeCollectionAddressChanged(address indexed newAddress);
    /// @notice Emitted when a note is posted to the darkpool
    /// @param noteCommitment The commitment to the note
    event NotePosted(uint256 indexed noteCommitment);

    // -----------
    // | Storage |
    // -----------

    // --- Fee Storage --- //

    /// @notice The protocol fee rate for the darkpool
    /// @dev This is the fixed point representation of a real number between 0 and 1.
    /// @dev To convert to its floating point representation, divide by the fixed point
    /// @dev precision, i.e. `fee = protocolFeeRate / FIXED_POINT_PRECISION`.
    /// @dev The current precision is `2 ** 63`.
    uint256 public protocolFeeRate;
    /// @notice The address at which external parties pay protocol fees
    /// @dev This is only used for external parties in atomic matches, fees for internal matches
    /// @dev and internal parties in atomic matches are paid via the `Note` mechanism.
    address public protocolFeeRecipient;
    /// @notice The public encryption key for the protocol's fees
    EncryptionKey public protocolFeeKey;
    /// @notice A per-asset fee override for the darkpool
    /// @dev This is used to set the protocol fee rate for atomic matches on a per-token basis
    /// @dev Only external match fees are overridden, internal match fees are always the protocol fee rate
    mapping(address => uint256) public perTokenFeeOverrides;

    // --- Delegate Addresses --- //

    /// @notice The hasher for the darkpool
    IHasher public hasher;
    /// @notice The verifier for the darkpool
    IVerifier public verifier;
    /// @notice The Permit2 contract instance for handling deposits
    IPermit2 public permit2;
    /// @notice The WETH9 contract instance used for depositing/withdrawing native tokens
    IWETH9 public weth;
    /// @notice The TransferExecutor contract for handling external transfers
    address public transferExecutor;

    // --- Protocol Level State Storage --- //

    /// @notice Bundled core darkpool state
    /// @dev Contains: openPublicIntents mapping, spentNonces mapping, merkleTree, and nullifierSet
    DarkpoolState private _state;

    // ---------------------------------
    // | Constructors and Initializers |
    // ---------------------------------

    /// @notice Constructor that disables initializers for the implementation contract
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() Ownable(msg.sender) {
        _disableInitializers();
    }

    /// @inheritdoc IDarkpoolV2
    function initialize(
        address initialOwner,
        uint256 protocolFeeRate_,
        address protocolFeeRecipient_,
        EncryptionKey memory protocolFeeKey_,
        IWETH9 weth_,
        IHasher hasher_,
        IVerifier verifier_,
        IPermit2 permit2_,
        address transferExecutor_
    )
        public
        initializer
    {
        _transferOwnership(initialOwner);

        protocolFeeRate = protocolFeeRate_;
        protocolFeeRecipient = protocolFeeRecipient_;
        protocolFeeKey = protocolFeeKey_;
        hasher = hasher_;
        verifier = verifier_;
        permit2 = permit2_;
        weth = weth_;
        transferExecutor = transferExecutor_;
    }

    // -----------------
    // | State Getters |
    // -----------------

    /// @inheritdoc IDarkpoolV2
    function openPublicIntents(bytes32 intentHash) public view returns (uint256) {
        return _state.getOpenIntentAmountRemaining(intentHash);
    }

    /// @inheritdoc IDarkpoolV2
    function nullifierSpent(BN254.ScalarField nullifier) public view returns (bool) {
        return _state.nullifierSpent(nullifier);
    }

    /// @inheritdoc IDarkpoolV2
    function rootInHistory(BN254.ScalarField root) public view returns (bool) {
        return _state.rootInHistory(root);
    }

    // -----------------
    // | State Updates |
    // -----------------

    // --- Deposit --- //

    /// @inheritdoc IDarkpoolV2
    function deposit(DepositAuth memory auth, DepositProofBundle calldata depositProofBundle) public {
        // 1. Verify the proof bundle
        bool valid = verifier.verifyExistingBalanceDepositValidity(depositProofBundle);
        if (!valid) revert DepositVerificationFailed();

        // 2. Execute the deposit
        Deposit memory depositInfo = depositProofBundle.statement.deposit;
        BN254.ScalarField newBalanceCommitment = depositProofBundle.statement.newBalanceCommitment;
        TransferLib.executePermit2SignatureDeposit(depositInfo, newBalanceCommitment, auth, permit2);

        // 3. Update the state; nullify the previous balance and insert the new balance
        uint256 merkleDepth = depositProofBundle.statement.merkleDepth;
        BN254.ScalarField balanceNullifier = depositProofBundle.statement.balanceNullifier;
        _state.spendNullifier(balanceNullifier);
        _state.insertMerkleLeaf(merkleDepth, newBalanceCommitment, hasher);
    }

    /// @inheritdoc IDarkpoolV2
    function depositNewBalance(address token, uint256 amount, address from) public {
        // TODO: Implement
    }

    // --- Withdrawal --- //

    /// @inheritdoc IDarkpoolV2
    function withdraw(address token, uint256 amount, address to) public {
        // TODO: Implement
    }

    // --- Fees --- //

    /// @inheritdoc IDarkpoolV2
    function payFees(address token, uint256 amount, address from) public {
        // TODO: Implement
    }

    // --------------
    // | Settlement |
    // --------------

    /// @inheritdoc IDarkpoolV2
    function settleMatch(
        ObligationBundle calldata obligationBundle,
        SettlementBundle calldata party0SettlementBundle,
        SettlementBundle calldata party1SettlementBundle
    )
        public
    {
        // 1. Allocate a settlement context
        SettlementContext memory settlementContext =
            SettlementLib.allocateSettlementContext(party0SettlementBundle, party1SettlementBundle);

        // 2. Validate that the settlement obligations are compatible with one another
        SettlementLib.validateObligationBundle(obligationBundle, settlementContext);

        // 3. Validate and authorize the settlement bundles
        SettlementLib.executeSettlementBundle(
            PartyId.PARTY_0, obligationBundle, party0SettlementBundle, settlementContext, _state, hasher
        );
        SettlementLib.executeSettlementBundle(
            PartyId.PARTY_1, obligationBundle, party1SettlementBundle, settlementContext, _state, hasher
        );

        // 4. Execute the transfers necessary for settlement
        // The helpers above will push transfers to the settlement context if necessary
        SettlementLib.executeTransfers(settlementContext, weth, permit2);

        // 5. Verify the proofs necessary for settlement
        // The helpers above will push proofs to the settlement context if necessary
        SettlementLib.verifySettlementProofs(settlementContext, verifier);
    }
}
