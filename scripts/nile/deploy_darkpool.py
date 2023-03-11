"""
Declares the Merkle tree impl, nullifier set impl, darkpool impl, and attaches this
all to a deployed proxy
"""

import logging

from nile.common import ETH_TOKEN_ADDRESS
from nile.core.types.account import Account
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

"""
Script
"""


async def run(nre: NileRuntimeEnvironment):
    """
    Declares the Merkle and Nullifier classes, along with the darkpool
    places all implementation classes into the proxy
    """
    logging.getLogger().setLevel(logging.INFO)

    # Find a set of pre-deployed accounts
    accounts = await nre.get_accounts(predeployed=True)
    account = accounts[0]

    # Declare all contracts
    await declare_contracts(nre, account)
    await deploy_proxy(nre, account)


async def declare_contracts(nre: NileRuntimeEnvironment, account: Account):
    """
    Declare the merkle tree impl, nullifier set impl, darkpool impl, and proxy
    """
    # Declare the Merkle tree implementation
    tx = await account.declare(MERKLE_CONTRACT_NAME, alias=MERKLE_CONTRACT_NAME)
    await tx.execute()

    # Declare the nullifier set implementation
    tx = await account.declare(NULLIFIER_CONTRACT_NAME, alias=NULLIFIER_CONTRACT_NAME)
    await tx.execute()

    # Declare the darkpool implementation
    tx = await account.declare(DARKPOOL_CONTRACT_NAME, alias=DARKPOOL_CONTRACT_NAME)
    await tx.execute()

    # Declare the proxy
    tx = await account.declare(PROXY_CONTRACT_NAME, alias=PROXY_CONTRACT_NAME)
    await tx.execute()


async def deploy_proxy(nre: NileRuntimeEnvironment, account: Account):
    """
    Deploy the proxy contract with the correct implementation hashes
    """
    # Fetch the class hashes of the implementations of the contracts
    merkle_hash = hex(nre.get_declaration(MERKLE_CONTRACT_NAME))
    nullifier_hash = hex(nre.get_declaration(NULLIFIER_CONTRACT_NAME))
    darkpool_hash = hex(nre.get_declaration(DARKPOOL_CONTRACT_NAME))

    # The darkpool's initializer
    darkpool_initializer_params = [
        account.address,  # admin account addr
        merkle_hash,
        nullifier_hash,
    ]

    # The calldata to the proxy
    proxy_calldata = [
        darkpool_hash,
        get_selector_from_name("initializer"),
        len(darkpool_initializer_params),
        *darkpool_initializer_params,
    ]

    # Deploy the proxy
    tx = await account.deploy_contract(
        PROXY_CONTRACT_NAME,
        123,  # salt
        42,  # unique
        proxy_calldata,
        alias=PROXY_CONTRACT_NAME,
    )
    await tx.execute()

    logging.info("\n🕺 Deployment finished!")
