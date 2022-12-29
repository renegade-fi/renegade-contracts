"""
Groups tests for the Merkle tree implementation
"""
import os
import pytest
import random

from typing import List

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
MERKLE_HEIGHT = 5
# The path to the Merkle tree contract source
MERKLE_FILE = os.path.join("contracts", "merkle", "Merkle.cairo")
# The number of historical roots stored by the Merkle contract
ROOT_HISTORY_LEN = 30
# The number of bits that can be stored in a Starkware felt
STARKWARE_FELT_BITS = 251

############
# Fixtures #
############


@pytest.fixture(scope="function")
async def merkle_contract(starknet_state: Starknet) -> StarknetContract:
    """
    Deploys the merkle tree contract and returns a reference to it
    """
    merkle_contract = await starknet_state.deploy(source=MERKLE_FILE)
    await merkle_contract.initializer(height=MERKLE_HEIGHT).execute()

    return merkle_contract


###########
# Helpers #
###########


def assert_power_of_2(n: int):
    """
    Asserts that the input is a power of 2
    """
    assert n & (n - 1) == 0 and n > 0


def compute_merkle_root(leaves: List[int]) -> int:
    """
    Computes the merkle root of the given
    """
    assert_power_of_2(len(leaves))

    res = leaves
    while len(res) > 1:
        res = [pedersen_hash(res[i], res[i + 1]) for i in range(0, len(res), 2)]

    return res[0]


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

    @pytest.mark.asyncio
    async def test_single_insert(self, merkle_contract: StarknetContract):
        """
        Tests that inserts into the tree update the root properly
        """
        # Compute the expected root of the first insert into the tree
        insert_value = random.getrandbits(STARKWARE_FELT_BITS)
        expected_root = insert_value

        n_elems = 2**MERKLE_HEIGHT
        leaf_data = [insert_value] + [EMPTY_LEAF_VAL] * (n_elems - 1)

        expected_root = compute_merkle_root(leaf_data)

        # Insert the value into the contract and check the root
        exec_info = await merkle_contract.insert(value=insert_value).execute()
        assert exec_info.result == (expected_root,)

    @pytest.mark.asycio
    async def test_multi_insert(self, merkle_contract: StarknetContract):
        """
        Tests that the root is updated properly when filling the Merkle tree
        """
        # Select a set of random set of values
        n_values = 2**MERKLE_HEIGHT
        leaf_values = [random.getrandbits(STARKWARE_FELT_BITS) for _ in range(n_values)]

        # Compute the expected merkle root
        expected_root = compute_merkle_root(leaf_values)

        # Insert into the contract's tree
        for value in leaf_values:
            exec_info = await merkle_contract.insert(value=value).execute()

        # Retreive the Merkle root after the insertions are complete
        exec_info = await merkle_contract.get_root(index=0).call()
        assert exec_info.result == (expected_root,)

    @pytest.mark.asyncio
    async def test_insert_full_tree(self, merkle_contract: StarknetContract):
        """
        Tests that inserting into a full tree fails
        """
        # Select a set of random set of values
        n_values = 2**MERKLE_HEIGHT
        leaf_values = [random.getrandbits(STARKWARE_FELT_BITS) for _ in range(n_values)]

        # Compute the expected merkle root
        expected_root = compute_merkle_root(leaf_values)

        # Insert into the contract's tree
        for value in leaf_values:
            await merkle_contract.insert(value=value).execute()

        await assert_revert(
            merkle_contract.insert(value=1).execute(), "merkle tree full"
        )
