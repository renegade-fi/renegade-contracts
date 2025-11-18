// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { TransparentUpgradeableProxy } from "oz-contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import { EncryptionKey } from "renegade-lib/Ciphertext.sol";
import { IDarkpoolV2 } from "darkpoolv2-interfaces/IDarkpoolV2.sol";
import { IHasher } from "renegade-lib/interfaces/IHasher.sol";
import { IVerifier } from "darkpoolv2-interfaces/IVerifier.sol";
import { IPermit2 } from "permit2-lib/interfaces/IPermit2.sol";
import { IWETH9 } from "renegade-lib/interfaces/IWETH9.sol";

/// @title DarkpoolV2Proxy
/// @author Renegade Eng
/// @notice This contract is a TransparentUpgradeableProxy for the DarkpoolV2 contract.
/// It simplifies deployment by accepting DarkpoolV2-specific initialization parameters
/// and encoding them appropriately.
contract DarkpoolV2Proxy is TransparentUpgradeableProxy {
    /// @notice Initializes a TransparentUpgradeableProxy for a DarkpoolV2 implementation.
    /// @param implementation The DarkpoolV2 implementation address
    /// @param admin The admin address - serves as both ProxyAdmin owner and DarkpoolV2 owner
    /// @param protocolFeeRate The protocol fee rate for the darkpool
    /// @param protocolFeeRecipient The address to receive protocol fees
    /// @param protocolFeeKey The encryption key for protocol fees
    /// @param weth The WETH9 contract instance
    /// @param hasher The hasher for the darkpool
    /// @param verifier The verifier for the darkpool
    /// @param permit2 The Permit2 contract instance for handling deposits
    /// @param transferExecutor The TransferExecutor contract address
    constructor(
        address implementation,
        address admin,
        // DarkpoolV2-specific initialization parameters
        uint256 protocolFeeRate,
        address protocolFeeRecipient,
        EncryptionKey memory protocolFeeKey,
        IWETH9 weth,
        IHasher hasher,
        IVerifier verifier,
        IPermit2 permit2,
        address transferExecutor
    )
        payable
        TransparentUpgradeableProxy(
            implementation,
            admin,
            abi.encodeWithSelector(
                IDarkpoolV2.initialize.selector,
                admin, // Use the same admin address for DarkpoolV2 owner
                protocolFeeRate,
                protocolFeeRecipient,
                protocolFeeKey,
                weth,
                hasher,
                verifier,
                permit2,
                transferExecutor
            )
        )
    { }
}
