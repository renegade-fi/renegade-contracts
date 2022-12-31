"""
Groups tests for the main contract's code
"""
import os

import pytest

from starkware.starknet.public.abi import get_selector_from_name
from starkware.starknet.testing.starknet import Starknet
from starkware.starknet.testing.contract import DeclaredClass, StarknetContract

from nile.utils import assert_revert, str_to_felt, to_uint

from util import random_felt, MockSigner
from test_merkle import empty_merkle_tree_root

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
        assert exec_info.call_info.retdata[1] == empty_merkle_tree_root(
            MERKLE_TREE_HEIGHT
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
        assert exec_info.call_info.retdata[1] == empty_merkle_tree_root(
            MERKLE_TREE_HEIGHT
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
        expected_root = empty_merkle_tree_root(MERKLE_TREE_HEIGHT)
        exec_info = await signer.send_transaction(
            admin_account, proxy_deploy.contract_address, "get_root", []
        )

        assert exec_info.call_info.retdata[1] == expected_root

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
            [commitment, nullifier, nullifier2, 0],
        )

        # Check that the nullifier is now used
        exec_info = await signer.send_transaction(
            admin_account,
            proxy_deploy.contract_address,
            "is_nullifier_used",
            [nullifier],
        )

        assert exec_info.call_info.retdata[1] == 1  # True


class TestDepositWithdraw:
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
            erc20_contract.contract_address,  # mint
            *amount_uint,  # amount
            0,  # deposit
        )
        await signer.send_transaction(
            admin_account,
            proxy.contract_address,
            "update_wallet",
            [
                wallet_commit,
                match_nullifier,
                settle_nullifier,
                1,
                *external_transfer_payload,
            ],
        )

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
            erc20_contract.contract_address,  # mint
            *amount_uint,  # amount
            1,  # withdraw
        )
        await signer.send_transaction(
            admin_account,
            proxy.contract_address,
            "update_wallet",
            [
                wallet_commit,
                match_nullifier,
                settle_nullifier,
                1,
                *external_transfer_payload,
            ],
        )

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
        await TestDepositWithdraw.deposit(
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
        await TestDepositWithdraw.deposit(
            ERC20_BALANCE, signer, admin_account, proxy_deploy, erc20_contract
        )

        # Now withdraw half
        half_balance = ERC20_BALANCE / 2
        await TestDepositWithdraw.withdraw(
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
                    1,
                    *external_transfer_payload,
                ],
            ),
            reverted_with="direction must be 0 or 1",
        )
