// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { IWETH9 } from "renegade-lib/interfaces/IWETH9.sol";
import { ERC20Mock } from "oz-contracts/mocks/token/ERC20Mock.sol";
import { SafeTransferLib } from "solmate/utils/SafeTransferLib.sol";

/// @title WethMock
/// @notice A mock implementation of the IWETH9 interface
contract WethMock is IWETH9, ERC20Mock {
    /// @notice Deposit ETH into the contract
    function deposit() external payable {
        _mint(msg.sender, msg.value);
    }

    /// @notice Withdraw ETH from the contract
    function withdraw(uint256 amount) external {
        _burn(msg.sender, amount);
        SafeTransferLib.safeTransferETH(msg.sender, amount);
    }
}
