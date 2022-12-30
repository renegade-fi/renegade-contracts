"""
Groups tests for the nullifier set
"""

import os
import pytest
import random

from nile.utils import assert_revert

from starkware.starknet.testing.starknet import Starknet
from starkware.starknet.testing.contract import StarknetContract

# The path to the nullifer set contract file
NULLIFIER_CONTRACT_PATH = os.path.join("contracts", "nullifier", "NullifierSet.cairo")
# The number of bits that can be stored in a Starkware felt
STARKWARE_FELT_BITS = 251


@pytest.fixture(scope="function")
async def nullifier_contract(starknet_state: Starknet) -> StarknetContract:
    """
    Deploys the nullifier set contract and returns a reference
    """
    nullifier_contract = await starknet_state.deploy(source=NULLIFIER_CONTRACT_PATH)
    await nullifier_contract.initializer().execute()

    return nullifier_contract


class TestNullifier:
    """
    Groups tests for the nullifier set
    """

    @pytest.mark.asyncio
    async def test_double_initialize(self, nullifier_contract: StarknetContract):
        """
        Tests that initializing twice fails
        """
        # The `merkle_contract` fixture has already initialized the contract,
        # call the `merkle_contract.intializer` method again and expect an error
        await assert_revert(
            nullifier_contract.initializer().execute(),
            reverted_with="Initializable: contract already initialized",
        )

    @pytest.mark.asyncio
    async def test_valid_nullifiers(self, nullifier_contract: StarknetContract):
        """
        Tests that a series of nullifiers used without conflict are valid
        """
        n_nullifiers = 20
        for _ in range(n_nullifiers):
            nullifier = random.getrandbits(STARKWARE_FELT_BITS)

            # Check used via call
            exec_info = await nullifier_contract.is_nullifier_used(
                nullifier=nullifier
            ).call()
            assert exec_info.result == (0,)

            # Spend the nullifier
            await nullifier_contract.mark_nullifier_used(nullifier=nullifier).execute()

    @pytest.mark.asyncio
    async def test_invalid_nullifier(self, nullifier_contract: StarknetContract):
        """
        Tests that using a nullifier twice will fail
        """
        nullifier = random.getrandbits(STARKWARE_FELT_BITS)

        # Check unused
        exec_info = await nullifier_contract.is_nullifier_used(
            nullifier=nullifier
        ).call()
        assert exec_info.result == (0,)

        # Use the nullifier
        await nullifier_contract.mark_nullifier_used(nullifier=nullifier).execute()

        # Check used
        exec_info = await nullifier_contract.is_nullifier_used(
            nullifier=nullifier
        ).call()
        assert exec_info.result == (1,)

        # Attempt to double spend, ensure that the contract errors
        await assert_revert(
            nullifier_contract.mark_nullifier_used(nullifier=nullifier).execute(),
            "nullifier already used",
        )
