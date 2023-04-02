"""
Declares a new darkpool implementation and switches the implementation pointer in the proxy contract
"""

import logging

from nile.common import ETH_TOKEN_ADDRESS
from nile.core.account import Account
from nile.nre import NileRuntimeEnvironment
from nile.utils import to_uint, hex_address
from starkware.starknet.public.abi import get_selector_from_name

"""
Constants
"""

DARKPOOL_CONTRACT_NAME = "Darkpool"
MERKLE_CONTRACT_NAME = "Merkle"
NULLIFIER_CONTRACT_NAME = "NullifierSet"
PROXY_CONTRACT_NAME = "Proxy"
MAX_FEE = 10**15

"""
Script
"""


async def run(nre: NileRuntimeEnvironment):
    """
    Declares a new Darkpool implementation and upgrades the contract
    """
    logging.getLogger().setLevel(logging.DEBUG)
    logging.getLogger().disabled = False

    # Find a set of pre-deployed accounts
    accounts = await nre.get_accounts()
    account: Account = accounts[0]

    account_nonce = await nre.get_nonce(contract_address=account.address)

    # Declare the darkpool implementation
    (darkpool_hash, _) = await account.declare(
        DARKPOOL_CONTRACT_NAME,
        alias=DARKPOOL_CONTRACT_NAME,
        nonce=account_nonce,
        max_fee=MAX_FEE,
        watch_mode="track",
    )
    account_nonce += 1

    proxy_addr, _ = nre.get_deployment(PROXY_CONTRACT_NAME)
    darkpool_hash = nre.get_declaration(DARKPOOL_CONTRACT_NAME)

    # Upgrade the darkpool in the proxy
    await account.send(
        proxy_addr,
        "upgrade",
        [darkpool_hash],
        nonce=account_nonce,
        max_fee=MAX_FEE,
        watch_mode="track",
    )

    logging.info("\n🕺 Darkpool upgraded!")
