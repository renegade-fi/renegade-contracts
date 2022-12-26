"""
Tests the upgradeability of the base implementation contracts
"""
import os

from typing import Tuple

import asyncio
import pytest

from starkware.starknet.public.abi import get_selector_from_name
from starkware.starknet.testing.starknet import Starknet
from starkware.starknet.testing.contract import DeclaredClass, StarknetContract

from util import cached_contract, MockSigner

# The path to the mock account contract source code
ACCOUNT_FILE = os.path.join("tests", "mocks", "Account.cairo")
# The path to the alternative, proxiable implementation with a dummy interface
ALTERNATIVE_IMPL_FILE = os.path.join("tests", "mocks", "ProxyImplementation.cairo")
# The path to the contract source code
CONTRACT_FILE = os.path.join("contracts", "contract.cairo")
# The path to the proxy contract source code
PROXY_FILE = os.path.join("contracts", "proxy", "Proxy.cairo")


@pytest.fixture(scope="module")
def private_key() -> int:
    """
    A mock public key for the user calling the contracts
    """
    return 12345  # dummy value


@pytest.fixture(scope="module")
def signer(private_key: int) -> MockSigner:
    """
    Constructs a mock transaction signer
    """
    return MockSigner(private_key)


@pytest.fixture(scope="module")
async def starknet_state() -> Starknet:
    """
    Bootstrap the StarkNet mock network

    For now this just creates the network with no special setup
    """
    return await Starknet.empty()


@pytest.fixture(scope="module")
async def admin_account(
    signer: MockSigner, starknet_state: Starknet
) -> StarknetContract:
    """
    Deploys an admin account that can be used for proxy admin ops
    """
    # Rebind inputs to their completed futures
    return await starknet_state.deploy(
        source=ACCOUNT_FILE, constructor_calldata=[signer.public_key]
    )


@pytest.fixture(scope="module")
async def alternative_impl_contract_class(starknet_state: Starknet) -> int:
    """
    Declares the alternative implementation and returns its class hash
    """
    return await starknet_state.declare(source=ALTERNATIVE_IMPL_FILE)


@pytest.fixture(scope="module")
async def proxy_deploy(
    admin_account: StarknetContract, starknet_state: Starknet
) -> StarknetContract:
    """
    Setup the proxy contract with an implementation contract behind it
    """
    # Declare the contract class for the implementation contract
    declare_class = await starknet_state.declare(source=CONTRACT_FILE)

    initializer_params = [admin_account.contract_address]
    proxy_calldata = [
        declare_class.class_hash,
        get_selector_from_name("initializer"),
        len(initializer_params),
        *initializer_params,
    ]

    proxy_contract = await starknet_state.deploy(
        source=PROXY_FILE, constructor_calldata=proxy_calldata
    )

    return admin_account, proxy_contract, declare_class


@pytest.mark.asyncio
async def test_upgrade(
    signer: MockSigner,
    proxy_deploy: Tuple[StarknetContract],
    alternative_impl_contract_class: DeclaredClass,
):
    """
    Tests that upgrading from the base implementation contract and back
    works properly
    """
    # Rebind inputs to their completed futures
    admin_contract, proxy_contract, impl_class = proxy_deploy

    # Send a transaction to implementation_v0, increase the balance, fetch the balance, assert
    # the correctness
    await signer.send_transaction(
        admin_contract, proxy_contract.contract_address, "increase_balance", [20]
    )
    exec_info = await signer.send_transaction(
        admin_contract, proxy_contract.contract_address, "get_balance", []
    )

    assert exec_info.call_info.retdata[1] == 20

    # Redirect the proxy to the alternative implementation
    await signer.send_transaction(
        admin_contract,
        proxy_contract.contract_address,
        "upgrade",
        [alternative_impl_contract_class.class_hash],
    )

    # Set the value, get the value, assert correctness
    await signer.send_transaction(
        admin_contract, proxy_contract.contract_address, "setValue", [30]
    )
    exec_info = await signer.send_transaction(
        admin_contract, proxy_contract.contract_address, "getValue", []
    )

    assert exec_info.call_info.retdata[1] == 30

    # Redirect the proxy back to the original implementation and check the stored value
    await signer.send_transaction(
        admin_contract,
        proxy_contract.contract_address,
        "upgrade",
        [impl_class.class_hash],
    )

    exec_info = await signer.send_transaction(
        admin_contract, proxy_contract.contract_address, "get_balance", []
    )
    assert exec_info.call_info.retdata[1] == 20
