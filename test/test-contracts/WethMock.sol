// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { IWETH9 } from "renegade-lib/interfaces/IWETH9.sol";
import { ERC20Mock } from "oz-contracts/mocks/token/ERC20Mock.sol";

/// @title WethMock
/// @notice A mock implementation of the IWETH9 interface
contract WethMock is IWETH9, ERC20Mock {
    /// @notice Deposit ETH into the contract
    function deposit() external payable {
        _mint(msg.sender, msg.value);
    }

    /// @notice Withdraw ETH from the contract
    function withdrawTo(address to, uint256 amount) external {
        _burn(msg.sender, amount);
        payable(to).transfer(amount);
    }
}
