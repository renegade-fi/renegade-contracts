// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { TransparentUpgradeableProxy } from "oz-contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import { IDarkpoolExecutor } from "darkpoolv1-lib/interfaces/IDarkpoolExecutor.sol";

/**
 * @title UniswapXExecutorProxy
 * @dev This contract is a TransparentUpgradeableProxy for the UniswapXExecutor contract.
 * It simplifies deployment by accepting executor-specific initialization parameters
 * and encoding them appropriately.
 */
contract UniswapXExecutorProxy is TransparentUpgradeableProxy {
    /**
     * @dev Initializes a TransparentUpgradeableProxy for a UniswapXExecutor implementation.
     *
     * @param implementation The UniswapXExecutor implementation address
     * @param admin The admin address - serves as both ProxyAdmin owner and UniswapXExecutor owner
     * @param darkpool The darkpool address
     * @param uniswapXReactor The UniswapX reactor address
     */
    constructor(
        address implementation,
        address admin,
        address darkpool,
        address uniswapXReactor
    )
        payable
        TransparentUpgradeableProxy(
            implementation,
            admin,
            abi.encodeWithSelector(IDarkpoolExecutor.initialize.selector, admin, darkpool, uniswapXReactor)
        )
    { }
}
