// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { IReactorCallback } from "uniswapx/interfaces/IReactorCallback.sol";
import { ResolvedOrder } from "uniswapx/base/ReactorStructs.sol";

import { Initializable } from "oz-contracts/proxy/utils/Initializable.sol";
import { Ownable } from "oz-contracts/access/Ownable.sol";
import { Ownable2Step } from "oz-contracts/access/Ownable2Step.sol";
import { Pausable } from "oz-contracts/utils/Pausable.sol";

/**
 * @title DarkpoolExecutor
 * @notice A wrapper contract that acts as a UniswapX executor for the darkpool
 * @dev This contract implements IReactorCallback to handle order execution callbacks from UniswapX
 * and routes them to the darkpool for settlement
 */
contract DarkpoolExecutor is IReactorCallback, Initializable, Ownable2Step, Pausable {
    // --- State Variables --- //

    /// @notice The darkpool contract
    address public darkpool;
    /// @notice The whitelisted caller
    /// @dev Practically this is the UniswapX order reactor
    address public whitelistedCaller;

    // --- Initializer --- //

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() Ownable(msg.sender) {
        _disableInitializers();
    }

    /// @notice Initializes the contract
    function initialize(address initialOwner, address darkpool_, address whitelistedCaller_) public initializer {
        _transferOwnership(initialOwner);
        darkpool = darkpool_;
        whitelistedCaller = whitelistedCaller_;
    }

    // --- Callback Logic --- //

    /// @notice Called by the reactor during the execution of an order
    /// @param resolvedOrders Has inputs and outputs
    /// @param callbackData The callbackData specified for an order execution
    /// @dev Must have approved each token and amount in outputs to the msg.sender
    function reactorCallback(ResolvedOrder[] memory resolvedOrders, bytes memory callbackData) external override {
        // TODO: Implement the callback logic
    }
}
