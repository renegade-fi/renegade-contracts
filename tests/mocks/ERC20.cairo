// A mock ERC20 mintable contract for testing deposit/withdraw
%lang starknet

from openzeppelin.token.erc20.presets.ERC20Mintable import (
    constructor,
    balanceOf,
    owner,
    transfer,
    transferFrom,
    approve,
    mint,
)
