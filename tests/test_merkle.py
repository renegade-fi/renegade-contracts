"""
Groups tests for the Merkle tree implementation
"""
import os
import pytest

from nile.utils import assert_revert

from starkware.starknet.testing.starknet import Starknet
from starkware.starknet.testing.contract import StarknetContract
from starkware.crypto.signature.fast_pedersen_hash import pedersen_hash
from starkware.starkware_utils.error_handling import StarkException

# The value on an empty leaf in the Merkle tree, defined to be keccak256('renegade')
# taken modulo the Cairo field
EMPTY_LEAF_VAL = (
    306932273398430716639340090025251549301604242969558673011416862133942957551
)
# The height of the Merkle tree used for testing
MERKLE_HEIGHT = 32
# The path to the Merkle tree contract source
MERKLE_FILE = os.path.join("contracts", "merkle", "Merkle.cairo")
# The number of historical roots stored by the Merkle contract
ROOT_HISTORY_LEN = 30


@pytest.fixture(scope="module")
async def merkle_contract(starknet_state: Starknet) -> StarknetContract:
    """
    Deploys the merkle tree contract and returns a reference to it
    """
    merkle_contract = await starknet_state.deploy(source=MERKLE_FILE)
    await merkle_contract.initializer(height=MERKLE_HEIGHT).execute()

    return merkle_contract


class TestMerkle:
    """
    Groups unit tests for the Merkle tree implementation
    """

    @pytest.mark.asyncio
    async def test_double_initialize(self, merkle_contract: StarknetContract):
        """
        Tests that the Merkle tree cannot be doubly initialized
        """
        # The `merkle_contract` fixture has already initialized the contract,
        # call the `merkle_contract.intializer` method again and expect an error
        await assert_revert(
            merkle_contract.initializer(height=MERKLE_HEIGHT).execute(),
            reverted_with="Initializable: contract already initialized",
        )

    @pytest.mark.asyncio
    async def test_initial_root(self, merkle_contract: StarknetContract):
        """
        Tests that fetching the root from a newly initialized contract returns the
        proper emptry tree root
        """
        # Compute the expected root value
        expected_root = EMPTY_LEAF_VAL
        for _ in range(MERKLE_HEIGHT):
            expected_root = pedersen_hash(expected_root, expected_root)

        # Fetch the roots in the history, all should be initialized to
        # the same value
        for _ in range(ROOT_HISTORY_LEN):
            exec_info = await merkle_contract.get_root(index=0).call()
            assert exec_info.result == (expected_root,)

        # Fetch an out of bounds value, expect an error
        await assert_revert(
            merkle_contract.get_root(index=ROOT_HISTORY_LEN).call(),
            "root index must be within history length",  # Expected substring
        )
