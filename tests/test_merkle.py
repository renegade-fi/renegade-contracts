"""
Groups tests for the Merkle tree implementation
"""
import os
import pytest

from starkware.starknet.testing.starknet import Starknet
from starkware.starknet.testing.contract import StarknetContract

from util import MockSigner

# The path to the Merkle tree contract source
MERKLE_FILE = os.path.join("contracts", "merkle", "Merkle.cairo")


@pytest.fixture(scope="module")
async def merkle_contract(starknet_state: Starknet) -> StarknetContract:
    """
    Deploys the merkle tree contract and returns a reference to it
    """
    return await starknet_state.deploy(source=MERKLE_FILE)


class TestMerkle:
    """
    Groups unit tests for the Merkle tree implementation
    """

    @pytest.mark.asyncio
    async def test_initial_root(signer: MockSigner, merkle_contract: StarknetContract):
        """
        Tests that fetching the root from a newly initialized contract returns the
        proper emptry tree root
        """
        exec_info = await merkle_contract.get_root(index=0).call()
        assert exec_info.result == (0,)
