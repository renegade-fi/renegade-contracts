"""
Groups tests for the main contract's code
"""
import os

import pytest

from typing import List

from starkware.cairo.common.hash_chain import compute_hash_chain
from starkware.starknet.public.abi import get_selector_from_name
from starkware.starknet.testing.starknet import Starknet
from starkware.starknet.testing.contract import DeclaredClass, StarknetContract

from nile.utils import assert_revert, str_to_felt, to_uint
from merkle import MerkleTree
from util import random_felt, MockSigner

#############
# Constants #
#############

# The path to the alternative, proxiable implementation with a dummy interface
ALTERNATIVE_IMPL_FILE = os.path.join("tests", "mocks", "ProxyImplementation.cairo")
# The path to the contract source code
CONTRACT_FILE = os.path.join("contracts", "darkpool", "Darkpool.cairo")
# The balance of the mock account in the ERC20 mint
ERC20_BALANCE = 1000
# The path to the mock ERC20 contract
ERC20_CONTRACT = os.path.join("tests", "mocks", "ERC20.cairo")
# The name of the ERC 20 token
ERC20_NAME = str_to_felt("TestToken")
# The symbol of the ERC 20 token
ERC20_SYMBOL = str_to_felt("TKN")
# The path to the Merkle tree contract source
MERKLE_FILE = os.path.join("contracts", "merkle", "Merkle.cairo")
# The height of the Merkle tree used in the contract
MERKLE_TREE_HEIGHT = 32
# The path to the nullifer set contract file
NULLIFIER_CONTRACT_PATH = os.path.join("contracts", "nullifier", "NullifierSet.cairo")
# The path to the proxy contract source code
PROXY_FILE = os.path.join("contracts", "proxy", "Proxy.cairo")

###########
# Helpers #
###########


def random_felts(n: int) -> List[int]:
    """
    Generates `n` random Starknet field elements
    """
    return [random_felt() for _ in range(0, n)]


############
# Fixtures #
############


@pytest.fixture(scope="function")
async def main_impl_contract_class(starknet_state: Starknet) -> DeclaredClass:
    """
    Declares the main contract implementation and returns its class hash
    """
    return await starknet_state.declare(source=CONTRACT_FILE)


@pytest.fixture(scope="function")
async def alternative_impl_contract_class(starknet_state: Starknet) -> DeclaredClass:
    """
    Declares the alternative implementation and returns its class hash
    """
    return await starknet_state.declare(source=ALTERNATIVE_IMPL_FILE)


@pytest.fixture(scope="function")
async def merkle_impl_contract_class(starknet_state: Starknet) -> DeclaredClass:
    """
    Declares the Merkle contract implementation and returns its class hash
    """
    return await starknet_state.declare(source=MERKLE_FILE)


@pytest.fixture(scope="function")
async def nullifier_impl_contract_class(starknet_state: Starknet) -> DeclaredClass:
    """
    Declares the nullifier set contract implementation and returns its class hash
    """
    return await starknet_state.declare(source=NULLIFIER_CONTRACT_PATH)


@pytest.fixture(scope="function")
async def erc20_contract(
    admin_account: StarknetContract, starknet_state: Starknet
) -> StarknetContract:
    """
    Deploys a mock ERC20 token and mints an initial supply to the admin
    """
    return await starknet_state.deploy(
        source=ERC20_CONTRACT,
        constructor_calldata=[
            ERC20_NAME,  # name
            ERC20_SYMBOL,  # symbol
            18,  # decimals
            *to_uint(ERC20_BALANCE),  # initial supply
            admin_account.contract_address,  # recipient
            admin_account.contract_address,  # owner
        ],
    )


@pytest.fixture(scope="function")
async def proxy_deploy(
    admin_account: StarknetContract,
    main_impl_contract_class: DeclaredClass,
    merkle_impl_contract_class: DeclaredClass,
    nullifier_impl_contract_class: DeclaredClass,
    starknet_state: Starknet,
) -> StarknetContract:
    """
    Setup the proxy contract with an implementation contract behind it
    """
    initializer_params = [
        admin_account.contract_address,
        merkle_impl_contract_class.class_hash,
        nullifier_impl_contract_class.class_hash,
    ]
    proxy_calldata = [
        main_impl_contract_class.class_hash,
        get_selector_from_name("initializer"),
        len(initializer_params),
        *initializer_params,
    ]

    proxy_contract = await starknet_state.deploy(
        source=PROXY_FILE, constructor_calldata=proxy_calldata
    )

    return proxy_contract


####################
# UUPS Proxy Tests #
####################


class TestProxy:
    @pytest.mark.asyncio
    async def test_upgrade(
        self,
        signer: MockSigner,
        admin_account: StarknetContract,
        proxy_deploy: StarknetContract,
        main_impl_contract_class: DeclaredClass,
        alternative_impl_contract_class: DeclaredClass,
    ):
        """
        Tests that upgrading from the base implementation contract and back
        works properly
        """
        # Send a transaction to implementation_v0, increase the balance, fetch the balance, assert
        # the correctness
        exec_info = await signer.send_transaction(
            admin_account, proxy_deploy.contract_address, "get_root", []
        )
        assert (
            exec_info.call_info.retdata[1]
            == MerkleTree(height=MERKLE_TREE_HEIGHT).get_root()
        )
        # Redirect the proxy to the alternative implementation
        await signer.send_transaction(
            admin_account,
            proxy_deploy.contract_address,
            "upgrade",
            [alternative_impl_contract_class.class_hash],
        )

        # Set the value, get the value, assert correctness
        await signer.send_transaction(
            admin_account, proxy_deploy.contract_address, "setValue", [30]
        )
        exec_info = await signer.send_transaction(
            admin_account, proxy_deploy.contract_address, "getValue", []
        )

        assert exec_info.call_info.retdata[1] == 30

        # Redirect the proxy back to the original implementation and check the stored value
        await signer.send_transaction(
            admin_account,
            proxy_deploy.contract_address,
            "upgrade",
            [main_impl_contract_class.class_hash],
        )

        exec_info = await signer.send_transaction(
            admin_account, proxy_deploy.contract_address, "get_root", []
        )
        assert (
            exec_info.call_info.retdata[1]
            == MerkleTree(height=MERKLE_TREE_HEIGHT).get_root()
        )


########################
# Contract Logic Tests #
########################


class TestInitialState:
    """
    Groups unit tests for the high level functionality of the main contract
    """

    @pytest.mark.asyncio
    async def test_get_root(
        self,
        signer: MockSigner,
        admin_account: StarknetContract,
        proxy_deploy: StarknetContract,
    ):
        """
        Tests the get_root method, after deploy it should be equal to the root of an
        empty Merkle tree
        """
        expected_root = MerkleTree(height=MERKLE_TREE_HEIGHT).get_root()

        # Test the `get_root` view
        exec_info = await signer.send_transaction(
            admin_account, proxy_deploy.contract_address, "get_root", []
        )
        assert exec_info.call_info.retdata[1] == expected_root

        # Test the `root_in_history` view
        exec_info = await signer.send_transaction(
            admin_account,
            proxy_deploy.contract_address,
            "root_in_history",
            [expected_root],
        )
        assert exec_info.call_info.retdata[1] == 1  # true

        exec_info = await signer.send_transaction(
            admin_account,
            proxy_deploy.contract_address,
            "root_in_history",
            [random_felt()],
        )
        assert exec_info.call_info.retdata[1] == 0  # false

    @pytest.mark.asyncio
    async def test_is_nullifier_used(
        self,
        signer: MockSigner,
        admin_account: StarknetContract,
        proxy_deploy: StarknetContract,
    ):
        """
        Tests the is_nullifier_used method
        """
        # Random nullifier should begin unused
        nullifier = random_felt()
        exec_info = await signer.send_transaction(
            admin_account,
            proxy_deploy.contract_address,
            "is_nullifier_used",
            [nullifier],
        )

        assert exec_info.call_info.retdata[1] == 0  # False

        # Use the nullifier via `wallet_update`
        commitment = random_felt()
        nullifier2 = random_felt()
        await signer.send_transaction(
            admin_account,
            proxy_deploy.contract_address,
            "update_wallet",
            # Zero the blobs used for transfers, encryption, and proofs
            [commitment, nullifier, nullifier2, 0, 0, 0, 0],
        )

        # Check that the nullifier is now used
        exec_info = await signer.send_transaction(
            admin_account,
            proxy_deploy.contract_address,
            "is_nullifier_used",
            [nullifier],
        )

        assert exec_info.call_info.retdata[1] == 1  # True


class TestWalletUpdate:
    """
    Groups tests for depositing, withdrawing from the darkpool
    """

    ###########
    # Helpers #
    ###########

    async def deposit(
        amount: int,
        signer: MockSigner,
        admin_account: StarknetContract,
        proxy: StarknetContract,
        erc20_contract: StarknetContract,
    ):
        """
        Deposit an amount of the ERC20 token into the darkpool
        Returns the new root and the wallet commitment that was used
        """
        amount_uint = to_uint(amount)
        wallet_commit = random_felt()
        match_nullifier = random_felt()
        settle_nullifier = random_felt()

        # Approve the darkpool to transfer the given amount to itself
        await signer.send_transaction(
            admin_account,
            erc20_contract.contract_address,
            "approve",
            [proxy.contract_address, *amount_uint],  # spender  # amount
        )

        # Transfer half of the token balance to the darkpool
        external_transfer_payload = (
            admin_account.contract_address,  # sender
            erc20_contract.contract_address,  # mint
            *amount_uint,  # amount
            0,  # deposit
        )
        exec_info = await signer.send_transaction(
            admin_account,
            proxy.contract_address,
            "update_wallet",
            [
                wallet_commit,
                match_nullifier,
                settle_nullifier,
                0,  # internal_transfer_ciphertext_len
                1,
                *external_transfer_payload,
                0,  # encryption_blob_len
                0,  # proof_blob_len
            ],
        )

        return exec_info.call_info.retdata[1], wallet_commit

    async def withdraw(
        amount: int,
        signer: MockSigner,
        admin_account: StarknetContract,
        proxy: StarknetContract,
        erc20_contract: StarknetContract,
    ):
        """
        Withdraw the given amount from the pool
        """
        amount_uint = to_uint(amount)
        wallet_commit = random_felt()
        match_nullifier = random_felt()
        settle_nullifier = random_felt()

        # Transfer half of the token balance to the darkpool
        external_transfer_payload = (
            admin_account.contract_address,  # recipient
            erc20_contract.contract_address,  # mint
            *amount_uint,  # amount
            1,  # withdraw
        )
        exec_info = await signer.send_transaction(
            admin_account,
            proxy.contract_address,
            "update_wallet",
            [
                wallet_commit,
                match_nullifier,
                settle_nullifier,
                0,  # internal_transfer_ciphertext_len
                1,
                *external_transfer_payload,
                0,  # encryption_blob_len
                0,  # proof_blob_len
            ],
        )

        return exec_info.call_info.retdata[1], wallet_commit

    #########
    # Tests #
    #########

    @pytest.mark.asyncio
    async def test_deposit(
        self,
        signer: MockSigner,
        admin_account: StarknetContract,
        proxy_deploy: StarknetContract,
        erc20_contract: StarknetContract,
    ):
        """
        Tests depositing into the darkpool
        """
        # Transfer half of the initial supply to the darkpool
        half_balance = ERC20_BALANCE / 2
        new_root, wallet_commit = await TestWalletUpdate.deposit(
            half_balance, signer, admin_account, proxy_deploy, erc20_contract
        )
        expected_root = MerkleTree.from_leaf_data(
            height=MERKLE_TREE_HEIGHT, leaves=[wallet_commit]
        ).get_root()

        assert new_root == expected_root

        # Check the balances of the darkpool contract and the depositer
        # both should now be at half of the initial supply
        expected = to_uint(half_balance)
        exec_info = await erc20_contract.balanceOf(
            account=admin_account.contract_address
        ).call()
        assert exec_info.result == (expected,)

        exec_info = await erc20_contract.balanceOf(
            account=proxy_deploy.contract_address
        ).call()
        assert exec_info.result == (expected,)

    @pytest.mark.asyncio
    async def test_withdraw(
        self,
        signer: MockSigner,
        admin_account: StarknetContract,
        proxy_deploy: StarknetContract,
        erc20_contract: StarknetContract,
    ):
        """
        Tests withdrawing from the darkpool
        """
        # First transfer the whole balance to the darkpool
        new_root, wallet_commit = await TestWalletUpdate.deposit(
            ERC20_BALANCE, signer, admin_account, proxy_deploy, erc20_contract
        )
        expected_root = MerkleTree.from_leaf_data(
            height=MERKLE_TREE_HEIGHT, leaves=[wallet_commit]
        ).get_root()
        assert expected_root == new_root

        # Now withdraw half
        half_balance = ERC20_BALANCE / 2
        await TestWalletUpdate.withdraw(
            half_balance, signer, admin_account, proxy_deploy, erc20_contract
        )

        # Check the balances of the darkpool contract and the depositer
        # both should now be at half of the initial supply
        expected = to_uint(half_balance)
        exec_info = await erc20_contract.balanceOf(
            account=admin_account.contract_address
        ).call()
        assert exec_info.result == (expected,)

        exec_info = await erc20_contract.balanceOf(
            account=proxy_deploy.contract_address
        ).call()
        assert exec_info.result == (expected,)

    @pytest.mark.asyncio
    async def test_invalid_direction(
        self,
        signer: MockSigner,
        admin_account: StarknetContract,
        proxy_deploy: StarknetContract,
        erc20_contract: StarknetContract,
    ):
        """
        Tests that attempting to call update_wallet with an external transfer that
        has an invalid direction (i.e. not zero or one) fails
        """
        amount_uint = to_uint(1)
        wallet_commit = random_felt()
        match_nullifier = random_felt()
        settle_nullifier = random_felt()

        # Transfer half of the token balance to the darkpool
        external_transfer_payload = (
            admin_account.contract_address,  # sender/receiver
            erc20_contract.contract_address,  # mint
            *amount_uint,  # amount
            2,  # invalid direction
        )
        await assert_revert(
            signer.send_transaction(
                admin_account,
                proxy_deploy.contract_address,
                "update_wallet",
                [
                    wallet_commit,
                    match_nullifier,
                    settle_nullifier,
                    0,  # internal_transfer_ciphertext_len
                    1,
                    *external_transfer_payload,
                    0,  # encryption_blob_len
                    0,  # proof_blob_len
                ],
            ),
            reverted_with="direction must be 0 or 1",
        )

    @pytest.mark.asyncio
    async def test_internal_transfer(
        self,
        signer: MockSigner,
        admin_account: StarknetContract,
        proxy_deploy: StarknetContract,
    ):
        """
        Tests that internal transfers are properly committed to in the state tree
        """
        wallet_commit = random_felt()
        match_nullifier = random_felt()
        settle_nullifier = random_felt()

        # Construct a mock internal transfer
        ciphertext_len = 5
        internal_transfer_ciphertext = [random_felt() for _ in range(ciphertext_len)]

        # Execute the internal transfer, assert that the new root has committed the transfer ciphertext
        exec_info = await signer.send_transaction(
            admin_account,
            proxy_deploy.contract_address,
            "update_wallet",
            [
                wallet_commit,
                match_nullifier,
                settle_nullifier,
                ciphertext_len,
                *internal_transfer_ciphertext,
                0,  # external_transfers_len
                0,  # encryption_blob_len
                0,  # proof_blob_len
            ],
        )

        ciphertext_commitment = compute_hash_chain(
            [ciphertext_len] + internal_transfer_ciphertext
        )
        tree = MerkleTree.from_leaf_data(
            height=MERKLE_TREE_HEIGHT, leaves=[wallet_commit, ciphertext_commitment]
        )

        assert exec_info.call_info.retdata[1] == tree.get_root()


class TestMatch:
    """
    Groups tests for the match/encumbering process
    """

    def get_match_calldata(
        match_nullifier1=None,
        match_nullifier2=None,
        party0_note_commit=None,
        party1_note_commit=None,
        relayer0_note_commit=None,
        relayer1_note_commit=None,
        protocol_note_commit=None,
    ) -> List[int]:
        """
        Sets up mock calldata for the `match` function
        """
        ciphertext_len = 5
        proof_blob_len = 10

        return [
            match_nullifier1 or random_felt(),
            match_nullifier2 or random_felt(),
            # Party 0 note commitment and ciphertext
            party0_note_commit or random_felt(),
            ciphertext_len,
            *random_felts(ciphertext_len),
            # Party 1 note commitment and ciphertext
            party1_note_commit or random_felt(),
            ciphertext_len,
            *random_felts(ciphertext_len),
            # Relayer 0 note commitment and ciphertext
            relayer0_note_commit or random_felt(),
            ciphertext_len,
            *random_felts(ciphertext_len),
            # Relayer 1 note commitment and ciphertext
            relayer1_note_commit or random_felt(),
            ciphertext_len,
            *random_felts(ciphertext_len),
            # Protocol note commitment and ciphertext
            protocol_note_commit or random_felt(),
            ciphertext_len,
            *random_felts(ciphertext_len),
            # Proof blob
            proof_blob_len,
            *random_felts(proof_blob_len),
        ]

    @pytest.mark.asyncio
    async def test_match_root(
        self,
        signer: MockSigner,
        admin_account: StarknetContract,
        proxy_deploy: StarknetContract,
    ):
        """
        Tests the basic functionality of executing a match, validates that
        the root is correctly updated
        """
        # Generate random nullifiers and match ciphertexts
        ciphertext_len = 5
        proof_blob_len = 10
        match_nullifier1 = random_felt()
        match_nullifier2 = random_felt()

        # Generate note commitments
        party0_note_commit = random_felt()
        party1_note_commit = random_felt()
        relayer0_note_commit = random_felt()
        relayer1_note_commit = random_felt()
        protocol_note_commit = random_felt()

        # Execute the match transaction
        calldata = TestMatch.get_match_calldata(
            party0_note_commit=party0_note_commit,
            party1_note_commit=party1_note_commit,
            relayer0_note_commit=relayer0_note_commit,
            relayer1_note_commit=relayer1_note_commit,
            protocol_note_commit=protocol_note_commit,
        )
        print(f"\n\ncalldata: {calldata}\n\n")
        exec_info = await signer.send_transaction(
            admin_account,
            proxy_deploy.contract_address,
            "match",
            calldata=calldata,
        )

        tree = MerkleTree.from_leaf_data(
            height=MERKLE_TREE_HEIGHT,
            leaves=[
                party0_note_commit,
                party1_note_commit,
                relayer0_note_commit,
                relayer1_note_commit,
                protocol_note_commit,
            ],
        )
        expected_root = tree.get_root()

        assert exec_info.call_info.retdata[1] == expected_root

    @pytest.mark.asyncio
    async def test_match_encumber(
        self,
        signer: MockSigner,
        admin_account: StarknetContract,
        proxy_deploy: StarknetContract,
        erc20_contract: StarknetContract,
    ):
        """
        Tests that once a match has occurred the wallet cannot be updated
        """
        # Generate random nullifiers and match ciphertexts
        ciphertext_len = 5
        match_nullifier1 = random_felt()
        match_nullifier2 = random_felt()

        # Execute the match transaction
        calldata = TestMatch.get_match_calldata(
            match_nullifier1=match_nullifier1, match_nullifier2=match_nullifier2
        )
        await signer.send_transaction(
            admin_account,
            proxy_deploy.contract_address,
            "match",
            calldata,
        )

        # Now attempt to withdraw a balance from the wallet using the same
        # wallet nullifier as above; tx should fail
        amount_uint = to_uint(10)
        wallet_commit1 = random_felt()
        wallet_commit2 = random_felt()
        settle_nullifier1 = random_felt()
        settle_nullifier2 = random_felt()

        external_transfer_payload = (
            admin_account.contract_address,  # account_addr
            erc20_contract.contract_address,  # mint
            *amount_uint,  # amount
            1,  # withdraw
        )

        # Create one withdraw transaction for each wallet
        wallet1_tx = signer.send_transaction(
            admin_account,
            proxy_deploy.contract_address,
            "update_wallet",
            [
                wallet_commit1,
                match_nullifier1,
                settle_nullifier1,
                0,  # internal_transfers_ciphertext_len
                1,
                *external_transfer_payload,
                0,  # encryption_blob_len
                0,  # proof_blob_len
            ],
        )

        wallet2_tx = signer.send_transaction(
            admin_account,
            proxy_deploy.contract_address,
            "update_wallet",
            [
                wallet_commit2,
                match_nullifier2,
                settle_nullifier2,
                0,  # internal_transfers_ciphertext_len
                1,
                *external_transfer_payload,
                0,  # encryption_blob_len
                0,  # proof_blob_len
            ],
        )

        await assert_revert(wallet1_tx, "nullifier already used")
        await assert_revert(wallet2_tx, "nullifier already used")


class TestSettle:
    """
    Groups tests for the note settle process
    """

    @pytest.mark.asyncio
    @pytest.mark.parametrize("from_internal_tx", [0, 1])
    async def test_settle(
        self,
        from_internal_tx: int,
        signer: MockSigner,
        admin_account: StarknetContract,
        proxy_deploy: StarknetContract,
    ):
        """
        Tests the flow of settling on a note that came from a match
        Attempts to double spend the note, verifies that this fails
        """
        # Spend the note and update the wallet
        wallet_commit = random_felt()
        match_nullifier = random_felt()
        spend_nullifier = random_felt()
        note_redeem_nullifier = random_felt()
        calldata = [
            from_internal_tx,
            wallet_commit,
            match_nullifier,
            spend_nullifier,
            note_redeem_nullifier,
        ]

        exec_info = await signer.send_transaction(
            admin_account, proxy_deploy.contract_address, "settle", calldata
        )

        # Verify that the Merkle root has updated correctly
        tree = MerkleTree.from_leaf_data(
            height=MERKLE_TREE_HEIGHT, leaves=[wallet_commit]
        )
        assert exec_info.call_info.retdata[1] == tree.get_root()

        # Attempt to spend the note a second time on the same wallet
        await assert_revert(
            signer.send_transaction(
                admin_account, proxy_deploy.contract_address, "settle", calldata
            ),
            reverted_with="nullifier already used",
        )

        # Attempt to spend the note a second time on a different wallet
        await assert_revert(
            signer.send_transaction(
                admin_account,
                proxy_deploy.contract_address,
                "settle",
                [
                    from_internal_tx,  # from_internal_transaction
                    random_felt(),  # wallet_commitment
                    random_felt(),  # match_nullifier
                    random_felt(),  # spend_nullifier
                    note_redeem_nullifier,
                ],
            ),
            reverted_with="nullifier already used",
        )

    @pytest.mark.asyncio
    @pytest.mark.parametrize("from_internal_tx", [0, 1])
    async def test_update_after_settle(
        self,
        from_internal_tx: int,
        signer: MockSigner,
        admin_account: StarknetContract,
        proxy_deploy: StarknetContract,
        erc20_contract: StarknetContract,
    ):
        """
        Attempts to update and match a wallet after an order has been settled on it
        verifies that both operations fail
        """
        # Settle an order on the wallet
        wallet_commit = random_felt()
        match_nullifier = random_felt()
        spend_nullifier = random_felt()
        note_redeem_nullifier = random_felt()

        await signer.send_transaction(
            admin_account,
            proxy_deploy.contract_address,
            "settle",
            [
                from_internal_tx,
                wallet_commit,
                match_nullifier,
                spend_nullifier,
                note_redeem_nullifier,
            ],
        )

        # Attempt to withdraw from the darkpool using the old wallet
        external_transfer_payload = (
            admin_account.contract_address, # account_addr
            erc20_contract.contract_address,  # mint
            *to_uint(10),  # amount
            1,  # withdraw
        )

        await assert_revert(
            signer.send_transaction(
                admin_account,
                proxy_deploy.contract_address,
                "update_wallet",
                [
                    wallet_commit,
                    match_nullifier,
                    spend_nullifier,
                    0,  # internal_transfers_ciphertext_len
                    1,
                    *external_transfer_payload,
                    0,  # encryption_blob_len
                    0,  # proof_blob_len
                ],
            ),
            reverted_with="nullifier already used",
        )

        # Attempt to make another match on the old wallet
        # We only assert this here for an internal tx, for a note settle
        # that is generated via match, it is assumed that a previous call
        # to match nullified the match_nullifier
        if from_internal_tx == 1:
            await assert_revert(
                signer.send_transaction(
                    admin_account,
                    proxy_deploy.contract_address,
                    "match",
                    TestMatch.get_match_calldata(match_nullifier1=match_nullifier),
                ),
                reverted_with="nullifier already used",
            )

    @pytest.mark.asyncio
    async def test_encumber_then_settle_internal(
        self,
        signer: MockSigner,
        admin_account: StarknetContract,
        proxy_deploy: StarknetContract,
    ):
        """
        Tests that a wallet cannot settle an internal transfer after
        being encumbered
        """
        # Match the wallet
        wallet_commit = random_felt()
        match_nullifier = random_felt()
        spend_nullifier = random_felt()
        note_redeem_nullifier = random_felt()

        calldata = TestMatch.get_match_calldata(match_nullifier1=match_nullifier)
        await signer.send_transaction(
            admin_account,
            proxy_deploy.contract_address,
            "match",
            calldata,
        )

        # Now attempt to settle a (separate) internal note, verify that this fails
        await assert_revert(
            signer.send_transaction(
                admin_account,
                proxy_deploy.contract_address,
                "settle",
                [
                    1,  # from_internal_transfer
                    wallet_commit,
                    match_nullifier,
                    spend_nullifier,
                    note_redeem_nullifier,
                ],
            ),
            reverted_with="nullifier already used",
        )
