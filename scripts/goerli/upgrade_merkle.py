"""
Upgrades the Merkle tree implementation in the contract
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
    Declares the new Merkle implementation class and changes the pointer in the contract
    """
    logging.getLogger().setLevel(logging.DEBUG)
    logging.getLogger().disabled = False

    # Find a set of pre-deployed accounts
    accounts = await nre.get_accounts()
    account: Account = accounts[0]

    account_nonce = await nre.get_nonce(contract_address=account.address)

    # Declare the new Merkle implementation
    (declared_hash, _) = await account.declare(
        MERKLE_CONTRACT_NAME,
        alias=MERKLE_CONTRACT_NAME,
        nonce=account_nonce,
        max_fee=MAX_FEE,
        watch_mode="track",
    )
    account_nonce += 1

    # Call the upgrade method on the new implementation hash
    await account.send(
        PROXY_CONTRACT_NAME,
        "upgrade_merkle",
        [declared_hash],
        nonce=account_nonce,
        max_fee=MAX_FEE,
        watch_mode="track",
    )

    logging.info("\n🕺 Merkle implementation upgraded!")
