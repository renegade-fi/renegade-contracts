"""
Sets up the darkpool contract and implementation classes along with
an ERC-20 contract for testing
"""

import logging
import sys
import os

from pathlib import Path


from nile.common import ETH_TOKEN_ADDRESS
from nile.core.account import Account
from nile.nre import NileRuntimeEnvironment
from nile.utils import to_uint, hex_address, str_to_felt
from starkware.starknet.public.abi import get_selector_from_name

"""
Modify the system path to include the scripts dir before
attempting relative imports
"""
CONTRACTS_ROOT_DIR = Path(__file__).parent.parent.parent
sys.path.append(str(CONTRACTS_ROOT_DIR))

from scripts.nile.deploy_darkpool import (
    declare_contracts,
    deploy_proxy,
    PROXY_CONTRACT_NAME,
)

"""
Constants
"""

# The location of the ERC-20 implementation to deploy
ERC_20_CONTRACT_FILE = "tests/mocks/ERC20.cairo"
# The name of the compiled contract artifact that the declare/deploy will refer to
ERC_20_CONTRACT_NAME = "ERC20"
# The initial balance of the admin account in the contact
ERC_20_INITIAL_BALANCE = 1000
# The name of the ERC 20 token
ERC20_NAME = str_to_felt("TestToken")
# The symbol of the ERC 20 token
ERC20_SYMBOL = str_to_felt("TKN")
# The file that caches localhost declarations
LOCALHOST_DECLARATIONS_FILE = "localhost.declarations.txt"
# The file that caches localhost deployments
LOCALHOST_DEPLOYMENTS_FILE = "localhost.deployments.txt"
# The max payable transaction fee
MAX_FEE = 10**25

"""
Script
"""


async def run(nre: NileRuntimeEnvironment):
    """
    Declares the Merkle and Nullifier classes, along with the darkpool
    places all implementation classes into the proxy
    """
    logging.getLogger().setLevel(logging.INFO)
    logging.getLogger().disabled = False

    # Remove cached declarations and deployments so that we can
    # declare/deploy fresh
    remove_declarations_cache()

    # Find a set of pre-deployed accounts
    accounts = await nre.get_accounts(predeployed=True)
    account: Account = accounts[0]

    account_nonce = await nre.get_nonce(contract_address=account.address)

    # Declare all contracts and deploy the darkpool proxy
    account_nonce = await declare_contracts(nre, account, account_nonce)
    await deploy_proxy(nre, account)
    account_nonce += 1

    # Deploy an ERC-20 token to the chain state and give the test account
    # an initial balance
    account_nonce = await deploy_erc20(nre, account, account_nonce)

    # Run the integration test
    await integration_test(nre, account, account_nonce)


def remove_declarations_cache():
    """
    Removes the localhost.declarations.txt and localhost.deployments.txt
    files so that we may re-declare and re-deploy the contracts
    """
    declarations_file = f"{CONTRACTS_ROOT_DIR}/{LOCALHOST_DECLARATIONS_FILE}"
    deployments_file = f"{CONTRACTS_ROOT_DIR}/{LOCALHOST_DEPLOYMENTS_FILE}"

    if os.path.isfile(declarations_file):
        os.remove(path=declarations_file)
    if os.path.isfile(deployments_file):
        os.remove(path=deployments_file)


async def deploy_erc20(
    nre: NileRuntimeEnvironment, account: Account, nonce: int
) -> int:
    """
    Deploys a mock ERC-20 contract
    """
    # Compile the contract
    current_file = Path(__file__)
    workspace_dir = current_file.parent.parent.parent.absolute()

    contract_path = f"{workspace_dir}/{ERC_20_CONTRACT_FILE}"

    res = nre.compile(contracts=[contract_path])

    # Declare the class
    await account.declare(
        ERC_20_CONTRACT_NAME,
        alias=ERC_20_CONTRACT_NAME,
        max_fee=MAX_FEE,
        nonce=nonce,
        watch_mode="track",
    )
    nonce += 1

    # Deploy the contract
    erc_20_class_hash = hex(nre.get_declaration(ERC_20_CONTRACT_NAME))

    deploy_calldata = [
        ERC20_NAME,
        ERC20_SYMBOL,
        18,  # decimals
        *to_uint(ERC_20_INITIAL_BALANCE),
        account.address,  # recipient
        account.address,  # owner
    ]
    await account.deploy_contract(
        ERC_20_CONTRACT_NAME,
        123,  # salt
        42,  # unique,
        deploy_calldata,
        alias=ERC_20_CONTRACT_NAME,
        max_fee=MAX_FEE,
        watch_mode="track",
    )

    return nonce


async def integration_test(
    nre: NileRuntimeEnvironment, account: Account, nonce: int
) -> int:
    """
    Test the update wallet deposit functionality
    """
    # Get the address of the proxy contract
    proxy_addr, _ = nre.get_deployment(PROXY_CONTRACT_NAME)
    erc20_addr, _ = nre.get_deployment(ERC_20_CONTRACT_NAME)
    logging.info(f"proxy address: {proxy_addr}\nerc20 addr: {erc20_addr}")

    # Approve the proxy to spend the initial supply on behalf of the signer
    approve_calldata = [proxy_addr, *to_uint(ERC_20_INITIAL_BALANCE)]
    await account.send(
        erc20_addr,
        get_selector_from_name("approve"),
        calldata=approve_calldata,
        watch_mode="track",
        max_fee=MAX_FEE,
        nonce=nonce,
    )
    nonce += 1

    # Call update wallet with an external transfer depositing into the darkpool
    external_transfer_tuple = (
        account.address,
        erc20_addr,
        *to_uint(ERC_20_INITIAL_BALANCE),
        0,
    )
    update_calldata = [
        123,  # commitment
        456,  # match nullifier
        789,  # spend nullifier
        0,  # internal transfer ciphertext len
        1,  # external transfers len
        *external_transfer_tuple,
        0,  # encryption blob len
        0,  # proof blob len
    ]

    await account.send(
        proxy_addr,
        get_selector_from_name("update_wallet"),
        calldata=update_calldata,
        watch_mode="track",
        max_fee=MAX_FEE,
        nonce=nonce,
    )
    nonce += 1

    return nonce
