// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ResolvedOrder } from "uniswapx/base/ReactorStructs.sol";
import { IReactorCallback } from "uniswapx/interfaces/IReactorCallback.sol";

interface IUniswapXExecutor is IReactorCallback {
    /// @notice Initializes the UniswapXExecutor
    /// @param initialOwner The address that will own the contract
    /// @param darkpool The darkpool address
    /// @param whitelistedCaller The whitelisted caller address
    function initialize(address initialOwner, address darkpool, address whitelistedCaller) external;
    /// @notice Returns the address of the current owner
    /// @return The address of the current owner
    function owner() external view returns (address);
}
