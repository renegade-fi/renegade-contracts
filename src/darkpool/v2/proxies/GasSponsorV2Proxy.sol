// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { TransparentUpgradeableProxy } from "oz-contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import { IGasSponsorV2 } from "darkpoolv2-interfaces/IGasSponsorV2.sol";

/// @title GasSponsorV2Proxy
/// @author Renegade Eng
/// @notice This contract is a TransparentUpgradeableProxy for the GasSponsorV2 contract.
/// It simplifies deployment by accepting GasSponsorV2-specific initialization parameters
/// and encoding them appropriately.
contract GasSponsorV2Proxy is TransparentUpgradeableProxy {
    /// @notice Initializes a TransparentUpgradeableProxy for a GasSponsorV2 implementation.
    /// @param implementation The GasSponsorV2 implementation address
    /// @param admin The admin address - serves as both ProxyAdmin owner and can manage proxy upgrades
    /// @param darkpoolAddress The address of the darkpool proxy contract
    /// @param authAddress The public key used to authenticate gas sponsorship
    constructor(
        address implementation,
        address admin,
        // GasSponsorV2-specific initialization parameters
        address darkpoolAddress,
        address authAddress
    )
        payable
        TransparentUpgradeableProxy(
            implementation,
            admin,
            abi.encodeWithSelector(IGasSponsorV2.initialize.selector, admin, darkpoolAddress, authAddress)
        )
    { }
}
