"""
Groups tests for the Merkle tree implementation
"""
import os
import pytest

from typing import List

from nile.utils import assert_revert

from starkware.starknet.testing.starknet import Starknet
from starkware.starknet.testing.contract import StarknetContract
from starkware.crypto.signature.fast_pedersen_hash import pedersen_hash
from starkware.starkware_utils.error_handling import StarkException

from merkle import MerkleTree, EMPTY_LEAF_VAL
from util import random_felt

# The height of the Merkle tree used for testing
MERKLE_HEIGHT = 5
# The path to the Merkle tree contract source
MERKLE_FILE = os.path.join("contracts", "merkle", "Merkle.cairo")
# The number of historical roots stored by the contract
MERKLE_ROOT_HISTORY_LENGTH = 30
# The number of historical roots stored by the Merkle contract
ROOT_HISTORY_LEN = 30


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


#####################
# Merkle Tree Tests #
#####################


class TestMerkle:
    """
    Groups unit tests for the Merkle tree implementation
    """

    @pytest.mark.asyncio
    async def test_initial_root(self, merkle_contract: StarknetContract):
        """
        Tests that fetching the root from a newly initialized contract returns the
        proper emptry tree root
        """
        # Compute the expected root value
        tree = MerkleTree(height=MERKLE_HEIGHT)
        expected_root = tree.get_root()

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
        insert_value = random_felt()
        tree = MerkleTree.from_leaf_data(height=MERKLE_HEIGHT, leaves=[insert_value])
        expected_root = tree.get_root()

        # Insert the value into the contract and check the root
        exec_info = await merkle_contract.insert(value=insert_value).execute()
        assert exec_info.result == (expected_root,)

    @pytest.mark.asyncio
    async def test_multi_insert(self, merkle_contract: StarknetContract):
        """
        Tests that the root is updated properly when filling the Merkle tree
        """
        # Select a set of random set of values
        n_values = 2**MERKLE_HEIGHT
        leaf_values = [random_felt() for _ in range(n_values)]

        tree = MerkleTree.from_leaf_data(height=MERKLE_HEIGHT, leaves=leaf_values)
        expected_root = tree.get_root()

        # Insert into the contract's tree
        for value in leaf_values:
            exec_info = await merkle_contract.insert(value=value).execute()

        # Retreive the Merkle root after the insertions are complete
        exec_info = await merkle_contract.get_root(index=0).call()
        assert exec_info.result == (expected_root,)

    @pytest.mark.asyncio
    async def test_root_history(self, merkle_contract: StarknetContract):
        """
        Tests that the Merkle history is properly formed as each insertion
        is executed
        """
        # Sample random leaf data
        n_insertions = 2**MERKLE_HEIGHT
        leaf_data = [random_felt() for _ in range(n_insertions)]

        # Incrementally insert the leaves and compute the expected history
        tree = MerkleTree(height=MERKLE_HEIGHT)
        expected_history = []
        for leaf in leaf_data:
            # Compute the partial root
            tree.insert(leaf)
            expected_history.append(tree.get_root())

        # Insert values into the Merkle history, check the new root as we progress
        for (expected_root, next_leaf) in zip(expected_history, leaf_data):
            exec_info = await merkle_contract.insert(value=next_leaf).execute()
            assert exec_info.result == (expected_root,)

        # Now test historial root queries
        # Truncate to the history size of Merkle contract history
        # The contract's history buffer is in reverse (newest is index 0)
        expected_history.reverse()
        expected_history = expected_history[:MERKLE_ROOT_HISTORY_LENGTH]

        for (i, expected_root) in enumerate(expected_history):
            exec_info = await merkle_contract.get_root(index=i).call()
            assert exec_info.result == (expected_root,)

    @pytest.mark.asyncio
    async def test_insert_full_tree(self, merkle_contract: StarknetContract):
        """
        Tests that inserting into a full tree fails
        """
        # Select a set of random set of values
        n_values = 2**MERKLE_HEIGHT
        leaf_values = [random_felt() for _ in range(n_values)]

        # Insert into the contract's tree
        for value in leaf_values:
            await merkle_contract.insert(value=value).execute()

        await assert_revert(
            merkle_contract.insert(value=1).execute(), "merkle tree full"
        )
