// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { IReactorCallback } from "uniswapx/interfaces/IReactorCallback.sol";
import { ResolvedOrder } from "uniswapx/base/ReactorStructs.sol";

import { Initializable } from "oz-contracts/proxy/utils/Initializable.sol";
import { Ownable } from "oz-contracts/access/Ownable.sol";
import { Ownable2Step } from "oz-contracts/access/Ownable2Step.sol";
import { Pausable } from "oz-contracts/utils/Pausable.sol";
import { IDarkpool } from "renegade-lib/interfaces/IDarkpool.sol";
import { IReactor } from "uniswapx/interfaces/IReactor.sol";
import { SignedOrder } from "uniswapx/base/ReactorStructs.sol";
import {
    PartyMatchPayload,
    MatchAtomicProofs,
    MatchAtomicLinkingProofs,
    MalleableMatchAtomicProofs
} from "renegade-lib/darkpool/types/Settlement.sol";
import {
    ValidMatchSettleAtomicStatement,
    ValidMalleableMatchSettleAtomicStatement
} from "renegade-lib/darkpool/PublicInputs.sol";

/**
 * @title DarkpoolExecutor
 * @notice A wrapper contract that acts as a UniswapX executor for the darkpool
 * @dev This contract implements IReactorCallback to handle order execution callbacks from UniswapX
 * and routes them to the darkpool for settlement
 */
contract DarkpoolExecutor is IReactorCallback, Initializable, Ownable2Step, Pausable {
    // --- State Variables --- //

    /// @notice The darkpool contract
    IDarkpool public darkpool;
    /// @notice The UniswapX reactor contract
    IReactor public uniswapXReactor;

    // --- Errors --- //

    /// @notice Thrown when the caller is not whitelisted
    error UnauthorizedCaller();

    // --- Initializer --- //

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() Ownable(msg.sender) {
        _disableInitializers();
    }

    /// @notice Initializes the contract
    function initialize(address initialOwner, address darkpool_, address uniswapXReactor_) public initializer {
        _transferOwnership(initialOwner);
        darkpool = IDarkpool(darkpool_);
        uniswapXReactor = IReactor(uniswapXReactor_);
    }

    // --- Order Execution --- //

    /// @notice Execute a UniswapX order with atomic match settlement
    /// @param order The signed order to execute
    /// @param internalPartyPayload The validity proofs for the internal party
    /// @param matchSettleStatement The statement (public inputs) of VALID MATCH SETTLE
    /// @param proofs The proofs for the match
    /// @param linkingProofs The proof-linking arguments for the match
    function executeAtomicMatchSettle(
        SignedOrder calldata order,
        PartyMatchPayload calldata internalPartyPayload,
        ValidMatchSettleAtomicStatement calldata matchSettleStatement,
        MatchAtomicProofs calldata proofs,
        MatchAtomicLinkingProofs calldata linkingProofs
    )
        external
        payable
        whenNotPaused
    {
        // Encode callback data for processAtomicMatchSettle
        bytes memory callbackData = abi.encodeWithSelector(
            darkpool.processAtomicMatchSettle.selector,
            address(uniswapXReactor), // receiver is always the reactor
            internalPartyPayload,
            matchSettleStatement,
            proofs,
            linkingProofs
        );

        // Call the reactor's executeWithCallback, which will call back to our reactorCallback
        uniswapXReactor.executeWithCallback{ value: msg.value }(order, callbackData);
    }

    /// @notice Execute a UniswapX order with malleable atomic match settlement
    /// @param order The signed order to execute
    /// @param quoteAmount The quote amount of the match, resolving in between the bounds
    /// @param baseAmount The base amount of the match, resolving in between the bounds
    /// @param internalPartyPayload The validity proofs for the internal party
    /// @param matchSettleStatement The statement (public inputs) of VALID MATCH SETTLE
    /// @param proofs The proofs for the match
    /// @param linkingProofs The proof-linking arguments for the match
    function executeMalleableAtomicMatchSettle(
        SignedOrder calldata order,
        uint256 quoteAmount,
        uint256 baseAmount,
        PartyMatchPayload calldata internalPartyPayload,
        ValidMalleableMatchSettleAtomicStatement calldata matchSettleStatement,
        MalleableMatchAtomicProofs calldata proofs,
        MatchAtomicLinkingProofs calldata linkingProofs
    )
        external
        payable
        whenNotPaused
    {
        // Encode callback data for processMalleableAtomicMatchSettle
        bytes memory callbackData = abi.encodeWithSelector(
            darkpool.processMalleableAtomicMatchSettle.selector,
            quoteAmount,
            baseAmount,
            address(uniswapXReactor), // receiver is always the reactor
            internalPartyPayload,
            matchSettleStatement,
            proofs,
            linkingProofs
        );

        // Call the reactor's executeWithCallback, which will call back to our reactorCallback
        uniswapXReactor.executeWithCallback{ value: msg.value }(order, callbackData);
    }

    // --- Callback Logic --- //

    /// @notice Called by the reactor during the execution of an order
    /// @param callbackData The callbackData specified for an order execution
    /// @dev Must have approved each token and amount in outputs to the msg.sender
    function reactorCallback(
        ResolvedOrder[] memory, /* resolvedOrders */
        bytes memory callbackData
    )
        external
        override
        whenNotPaused
    {
        // Only the reactor may call this function
        if (msg.sender != address(uniswapXReactor)) revert UnauthorizedCaller();

        // Any ether balance present in the contract is meant as input to the darkpool trade
        // TODO: Properly account for the ether value of the transaction
        uint256 value = address(this).balance;

        // Forward the call directly to the darkpool
        // The callback data already contains the selector and all properly encoded parameters
        (bool success,) = address(darkpool).call{ value: value }(callbackData);
        require(success, "Darkpool call failed");
    }
}
