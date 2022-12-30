import os
import random

import asyncio
import pytest

from starkware.starknet.testing.starknet import Starknet
from starkware.starknet.testing.contract import StarknetContract

from util import MockSigner

# The path to the mock account contract source code
ACCOUNT_FILE = os.path.join("tests", "mocks", "Account.cairo")

############
# Fixtures #
############


@pytest.fixture(scope="module")
def event_loop():
    return asyncio.new_event_loop()


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
