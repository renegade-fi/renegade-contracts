// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { DarkpoolExecutor } from "renegade-executor/DarkpoolExecutor.sol";
import { UniswapXExecutorProxy } from "proxies/UniswapXExecutorProxy.sol";
import { IUniswapXExecutor } from "renegade-lib/interfaces/IUniswapXExecutor.sol";

import { IPermit2 } from "permit2-lib/interfaces/IPermit2.sol";
import { DarkpoolTestBase } from "test/darkpool/DarkpoolTestBase.sol";

import { PriorityOrderReactor } from "uniswapx/reactors/PriorityOrderReactor.sol";

/// @title UniswapXExecutorTest
/// @notice Test contract for the UniswapXExecutor
/// @dev This contract tests the UniswapXExecutor contract
contract UniswapXExecutorTest is DarkpoolTestBase {
    PriorityOrderReactor reactor;
    IUniswapXExecutor executor;

    /// @notice Sets up the test environment
    /// @dev For now we test against a `PriorityOrderReactor`, which is the flavor deployed on Base
    function setUp() public override {
        // Deploy the darkpool and tokens
        super.setUp();
        address protocolFeeOwner = vm.randomAddress();

        // Deploy the reactor
        reactor = new PriorityOrderReactor(permit2, protocolFeeOwner);

        // Initialize the UniswapXExecutorProxy
        DarkpoolExecutor executorImpl = new DarkpoolExecutor();
        UniswapXExecutorProxy executorProxy =
            new UniswapXExecutorProxy(address(executorImpl), darkpoolOwner, address(darkpool), address(reactor));
        executor = IUniswapXExecutor(address(executorProxy));
    }

    /// @notice Test that the owner is set correctly
    function testOwner() public {
        // Check that the owner is set correctly
        assertEq(executor.owner(), darkpoolOwner);
    }
}
