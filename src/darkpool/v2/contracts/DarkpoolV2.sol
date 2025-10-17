// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { Initializable } from "oz-contracts/proxy/utils/Initializable.sol";
import { Ownable } from "oz-contracts/access/Ownable.sol";
import { Ownable2Step } from "oz-contracts/access/Ownable2Step.sol";
import { Pausable } from "oz-contracts/utils/Pausable.sol";
import { IPermit2 } from "permit2-lib/interfaces/IPermit2.sol";

import { IHasher } from "renegade-lib/interfaces/IHasher.sol";
import { IVerifier } from "renegade-lib/interfaces/IVerifier.sol";
import { IWETH9 } from "renegade-lib/interfaces/IWETH9.sol";

import { BN254 } from "solidity-bn254/BN254.sol";

import { MerkleTreeLib } from "renegade-lib/merkle/MerkleTree.sol";
import { NullifierLib } from "renegade-lib/NullifierSet.sol";

import { EncryptionKey } from "darkpoolv1-types/Ciphertext.sol";

import { SettlementBundle } from "darkpoolv2-types/Settlement.sol";
import { SettlementLib } from "darkpoolv2-lib/settlement/SettlementLib.sol";

/// @title DarkpoolV2
/// @author Renegade Eng
/// @notice V2 of the Renegade darkpool contract for private trading
contract DarkpoolV2 is Initializable, Ownable2Step, Pausable {
    using MerkleTreeLib for MerkleTreeLib.MerkleTree;
    using NullifierLib for NullifierLib.NullifierSet;

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

    /// @notice The mapping of open public intents
    /// @dev This maps the intent hash to the amount remaining.
    /// @dev An intent hash is a hash of the tuple (executor, intent),
    /// where executor is the address of the party allowed to fill the intent.
    mapping(bytes32 => uint256) private openPublicIntents;
    /// @notice The Merkle tree for wallet commitments
    MerkleTreeLib.MerkleTree private merkleTree;
    /// @notice The nullifier set for the darkpool
    /// @dev Each time a wallet is updated (placing an order, settling a match, depositing, etc) a nullifier is spent.
    /// @dev This ensures that a pre-update wallet cannot create two separate post-update wallets in the Merkle state
    /// @dev The nullifier is computed deterministically from the shares of the pre-update wallet
    NullifierLib.NullifierSet private nullifierSet;
    /// @notice The set of public blinder shares that have been inserted into the darkpool
    /// @dev We track this to prevent duplicate blinders that may affect the ability of indexers to uniquely
    /// @dev recover a wallet
    NullifierLib.NullifierSet private publicBlinderSet;

    // ---------------------------------
    // | Constructors and Initializers |
    // ---------------------------------

    /// @notice Constructor that disables initializers for the implementation contract
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() Ownable(msg.sender) {
        _disableInitializers();
    }

    /// @notice Initialize the darkpool
    /// @param initialOwner The address that will own the contract
    /// @param protocolFeeRate_ The protocol fee rate for the darkpool
    /// @param protocolFeeRecipient_ The address to receive protocol fees
    /// @param protocolFeeKey_ The encryption key for protocol fees
    /// @param weth_ The WETH9 contract instance
    /// @param hasher_ The hasher for the darkpool
    /// @param verifier_ The verifier for the darkpool
    /// @param permit2_ The Permit2 contract instance for handling deposits
    /// @param transferExecutor_ The TransferExecutor contract address
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
        merkleTree.initialize();
    }

    // -----------------
    // | State Getters |
    // -----------------

    /// @notice Check if a nullifier has been spent
    /// @param nullifier The nullifier to check
    /// @return Whether the nullifier has been spent
    function nullifierSpent(BN254.ScalarField nullifier) public view returns (bool) {
        return nullifierSet.isSpent(nullifier);
    }

    // --------------
    // | Settlement |
    // --------------

    /// @notice Settle a trade
    /// @param party0SettlementBundle The settlement bundle for the first party
    /// @param party1SettlementBundle The settlement bundle for the second party
    function settleMatch(
        SettlementBundle calldata party0SettlementBundle,
        SettlementBundle calldata party1SettlementBundle
    )
        public
    {
        // 1. Validate that the settlement obligations are compatible with one another
        SettlementLib.checkObligationCompatibility(party0SettlementBundle.obligation, party1SettlementBundle.obligation);

        // 2. Authorize the intents in the settlement bundles
        SettlementLib.validateSettlementBundle(party0SettlementBundle, openPublicIntents);
        SettlementLib.validateSettlementBundle(party1SettlementBundle, openPublicIntents);

        // 3. After the settlement bundles are validated, update the darkpool's state
        // TODO: In this step, we re-decode the settlement bundles to operate on data. We mostly do
        // this to handle both bundles simultaneously for e.g. ERC20 transfers. We could defer transfers
        // to the end of the method like we do proofs, and operate on the decoded data all at once.
        SettlementLib.updateDarkpoolState(party0SettlementBundle, party1SettlementBundle, weth);

        // TODO: Verify proofs necessary for each step here
    }
}
