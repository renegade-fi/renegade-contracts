"""
Tests the upgradeability of the base implementation contracts
"""
import os

from typing import Tuple

import asyncio
import pytest

from starkware.starknet.public.abi import get_selector_from_name
from starkware.starknet.testing.starknet import Starknet
from starkware.starknet.testing.contract import StarknetContract

from util import cached_contract, MockSigner

# The path to the mock account contract source code
ACCOUNT_FILE = os.path.join("tests", "mocks", "Account.cairo")
# The path to the contract source code
CONTRACT_FILE = os.path.join("contracts", "contract.cairo")
# The path to the proxy contract source code
PROXY_FILE = os.path.join("contracts", "proxy", "Proxy.cairo")

@pytest.fixture(scope='module')
def private_key() -> int:
    """
    A mock public key for the user calling the contracts 
    """
    return 12345 # dummy value

@pytest.fixture(scope='module')
def signer(private_key: int) -> MockSigner:
    """
    Constructs a mock transaction signer 
    """
    return MockSigner(private_key)

@pytest.fixture(scope='module')
async def starknet_state() -> Starknet:
    """
    Bootstrap the StarkNet mock network

    For now this just creates the network with no special setup
    """
    return await Starknet.empty()

@pytest.fixture(scope='module')
async def admin_account(signer: MockSigner, starknet_state: Starknet) -> StarknetContract:
    """
    Deploys an admin account that can be used for proxy admin ops 
    """
    # Rebind inputs to their completed futures
    return await starknet_state.deploy(
        source = ACCOUNT_FILE,
        constructor_calldata=[signer.public_key]
    )

@pytest.fixture(scope='module')
async def proxy_deploy(admin_account: StarknetContract, starknet_state: Starknet) -> StarknetContract:
    """
    Setup the proxy contract with an implementation contract behind it
    """
    # Declare the contract class for the implementation contract
    declare_class = await starknet_state.declare(
        source=CONTRACT_FILE 
    )

    initializer_params = [admin_account.contract_address]
    proxy_calldata = [
        declare_class.class_hash,
        get_selector_from_name('initializer'),
        len(initializer_params),
        *initializer_params
    ]

    proxy_contract = await starknet_state.deploy(
        source=PROXY_FILE,
        constructor_calldata=proxy_calldata
    )

    return admin_account, proxy_contract

@pytest.mark.asyncio
async def test_upgrade(signer: MockSigner, proxy_deploy: Tuple[StarknetContract]):
    """
    Tests that upgrading from the base implementation contract and back
    works properly
    """
    # Rebind inputs to their completed futures
    admin_contract, proxy_contract = proxy_deploy

    print(f"Admin account: {admin_contract.contract_address}\n\n\n")
    print(f"Proxy account: {proxy_contract.contract_address}\n\n\n")

    # Send a transaction to implementation_v0
    exec_info = await signer.send_transaction(
        admin_contract, proxy_contract.contract_address, 'get_balance', []
    )
    
    assert exec_info.call_info.retdata[1] == 0
 

        