"""
An implementation of a merkle tree for testing
"""
import pytest

from collections import defaultdict
from dataclasses import dataclass
from typing import DefaultDict, List

from starkware.crypto.signature.fast_pedersen_hash import pedersen_hash

#############
# Constants #
#############

# The value on an empty leaf in the Merkle tree, defined to be keccak256('renegade')
# taken modulo the Cairo field
EMPTY_LEAF_VAL = (
    306932273398430716639340090025251549301604242969558673011416862133942957551
)

###############
# Merkle Tree #
###############


@dataclass(frozen=True, eq=True)
class MerkleNodeKey:
    """
    A key into the default dict
    """

    # The height in the Merkle tree that this node occurs at
    # height 0 is the root
    height: int
    # The index of the node in the list of nodes at the given height
    # the leftmost node is at index 0
    index: int


class MerkleTree:
    """
    A simple implementation of a Merkle tree for testing using the
    StarkNet pedersen hash. Implemented sparsely
    """

    # The height of the tree
    height: int
    # A sparse representation of the entires in the tree
    merkle_entries: DefaultDict[MerkleNodeKey, int]
    # The next leaf index that is unoccupied
    next_leaf: int
    # The current root of the tree
    root: int
    # The zero value of each tree
    zeros: List[int]

    def __init__(self, height: int):
        """
        Initializes the Merkle tree
        """
        self.height = height
        self.next_leaf = 0
        self.zeros = []
        self.merkle_entries = dict()
        self.root = self._initialize_zeros()

    def _initialize_zeros(self) -> int:
        """
        Setup the zero values at each level of the tree

        :return: The root of the empty tree
        """
        current_empty_value = EMPTY_LEAF_VAL
        for _ in range(self.height):
            # Append and hash with self to get the empty value for the next level in the tree
            self.zeros.append(current_empty_value)
            current_empty_value = pedersen_hash(
                current_empty_value, current_empty_value
            )

        # Reverse the zeros list so that index 0 is the root
        self.zeros.reverse()
        return current_empty_value

    def from_leaf_data(height: int, leaves: List[int]):
        """
        Construct a Merkle tree with a given set of leaves to begin
        """
        tree = MerkleTree(height)
        for leaf in leaves:
            tree.insert(leaf)

        return tree

    def get_root(self) -> int:
        """
        Returns the current root of the Merkle tree
        """
        return self.root

    def insert(self, value: int) -> int:
        """
        Insert a value into the tree, returns the root
        """
        assert self.next_leaf < 2**self.height, "tree full"

        # Compute a new root and update the index
        new_root = self._insert_impl(value, self.next_leaf, self.height)
        self.root = new_root
        self.next_leaf += 1

        return new_root

    def _insert_impl(self, value: int, index: int, height: int) -> int:
        """
        Insert a value into the tree recursively

        :param value: The value to insert into the tree
        :param index: The index in the current height to insert at
        :param height: The current height of the recursion in the tree

        :return: The new root after insertion
        """
        if height == 0:
            return value

        # Insert the value into the sparse storage
        self.merkle_entries[MerkleNodeKey(height, index)] = value

        # Select the index of the neighbor to hash with, if the current insertion
        # index is 0 (mod 2) then it is a left hand node, otherwise it is a right
        # hand node
        neighbor_index = index + 1 if index % 2 == 0 else index - 1
        neighbor = self.merkle_entries.get(
            MerkleNodeKey(height, neighbor_index),
            self.zeros[height - 1],
        )

        next_value = (
            pedersen_hash(value, neighbor)
            if index % 2 == 0
            else pedersen_hash(neighbor, value)
        )

        # Compute the index of the parent node in the tree
        parent_index = index // 2

        return self._insert_impl(next_value, parent_index, height - 1)
