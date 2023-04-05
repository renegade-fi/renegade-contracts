"""
From OpenZeppelin testing utils:
https://github.com/OpenZeppelin/cairo-contracts/blob/main/tests/utils.py
"""
import os
import random

from typing import Tuple
from pathlib import Path

from starkware.crypto.signature.fast_pedersen_hash import pedersen_hash
from starkware.starknet.business_logic.execution.objects import OrderedEvent
from starkware.starknet.business_logic.transaction.objects import (
    InternalTransaction,
    InternalDeclare,
    TransactionExecutionInfo,
)
from starkware.starknet.compiler.compile import compile_starknet_files
from starkware.starknet.core.os.class_hash import compute_class_hash
from starkware.starknet.core.os.transaction_hash.transaction_hash import (
    TransactionHashPrefix,
)
from starkware.starknet.core.os.contract_address.contract_address import (
    calculate_contract_address_from_hash,
)
from starkware.starknet.definitions.general_config import StarknetChainId
from starkware.starknet.public.abi import get_selector_from_name
from starkware.starknet.services.api.gateway.transaction import (
    InvokeFunction,
    DeployAccount,
)
from starkware.starknet.testing.starknet import StarknetContract
from starkware.starknet.testing.starknet import Starknet

from nile.signer import (
    Signer,
    from_call_to_call_array,
    get_transaction_hash,
    TRANSACTION_VERSION,
)

#############
# Constants #
#############

# The number of bits that can be stored in a Starkware felt
STARKWARE_FELT_BITS = 251

###########
# Helpers #
###########


def random_felt() -> int:
    """
    Samples a random 251 bit felt
    """
    return random.getrandbits(STARKWARE_FELT_BITS)


"""
Setup Utils from Openzeppelin's test utils:
https://github.com/OpenZeppelin/cairo-contracts/blob/main/tests/utils.py
"""

MAX_UINT256 = (2**128 - 1, 2**128 - 1)
INVALID_UINT256 = (MAX_UINT256[0] + 1, MAX_UINT256[1])
ZERO_ADDRESS = 0
TRUE = 1
FALSE = 0
IACCOUNT_ID = 0xA66BD575

_root = Path(__file__).parent.parent


def get_cairo_path():
    CAIRO_PATH = os.getenv("CAIRO_PATH")
    cairo_path = []

    if CAIRO_PATH is not None:
        cairo_path = [p for p in CAIRO_PATH.split(":")]

    return cairo_path


def contract_path(name):
    if name.startswith("tests/"):
        return str(_root / name)
    else:
        return str(_root / "src" / name)


def assert_event_emitted(tx_exec_info, from_address, name, data, order=0):
    """Assert one single event is fired with correct data."""
    assert_events_emitted(tx_exec_info, [(order, from_address, name, data)])


def assert_events_emitted(tx_exec_info, events):
    """Assert events are fired with correct data."""
    for event in events:
        order, from_address, name, data = event
        event_obj = OrderedEvent(
            order=order,
            keys=[get_selector_from_name(name)],
            data=data,
        )

        base = tx_exec_info.call_info.internal_calls[0]
        if event_obj in base.events and from_address == base.contract_address:
            return

        try:
            base2 = base.internal_calls[0]
            if event_obj in base2.events and from_address == base2.contract_address:
                return
        except IndexError:
            pass

        raise BaseException("Event not fired or not fired correctly")


def _get_path_from_name(name):
    """Return the contract path by contract name."""
    dirs = ["contracts", "tests/mocks"]
    for dir in dirs:
        for (dirpath, _, filenames) in os.walk(dir):
            for file in filenames:
                if file == f"{name}.cairo":
                    return os.path.join(dirpath, file)

    raise FileNotFoundError(f"Cannot find '{name}'.")


def get_contract_class(contract, is_path=False):
    """Return the contract class from the contract name or path"""
    if is_path:
        path = contract_path(contract)
    else:
        path = _get_path_from_name(contract)

    contract_class = compile_starknet_files(
        files=[path], debug_info=True, cairo_path=get_cairo_path()
    )
    return contract_class


def get_class_hash(contract_name, is_path=False):
    """Return the class_hash for a given contract."""
    contract_class = get_contract_class(contract_name, is_path)
    return compute_class_hash(contract_class=contract_class, hash_func=pedersen_hash)


def cached_contract(state, _class, deployed):
    """Return the cached contract"""
    contract = StarknetContract(
        state=state,
        abi=_class.abi,
        contract_address=deployed.contract_address,
        deploy_call_info=deployed.deploy_call_info,
    )
    return contract


"""
Signers from Openzeppelin's test util Signers:
https://github.com/OpenZeppelin/cairo-contracts/blob/main/tests/signers.py
"""


class BaseSigner:
    async def send_transaction(
        self, account, to, selector_name, calldata, nonce=None, max_fee=0
    ) -> TransactionExecutionInfo:
        return await self.send_transactions(
            account, [(to, selector_name, calldata)], nonce, max_fee
        )

    async def send_transactions(
        self, account, calls, nonce=None, max_fee=0
    ) -> Tuple[int, TransactionExecutionInfo]:
        raw_invocation = get_raw_invoke(account, calls)
        state = raw_invocation.state

        if nonce is None:
            nonce = await state.state.get_nonce_at(account.contract_address)

        transaction_hash = get_transaction_hash(
            prefix=TransactionHashPrefix.INVOKE,
            account=account.contract_address,
            calldata=raw_invocation.calldata,
            version=TRANSACTION_VERSION,
            chain_id=StarknetChainId.TESTNET.value,
            nonce=nonce,
            max_fee=max_fee,
        )

        signature = self.sign(transaction_hash)

        external_tx = InvokeFunction(
            contract_address=account.contract_address,
            calldata=raw_invocation.calldata,
            entry_point_selector=None,
            signature=signature,
            max_fee=max_fee,
            version=TRANSACTION_VERSION,
            nonce=nonce,
        )

        tx = InternalTransaction.from_external(
            external_tx=external_tx, general_config=state.general_config
        )
        execution_info = await state.execute_tx(tx=tx)
        return transaction_hash, execution_info

    async def declare_class(
        self,
        account,
        contract_name,
        nonce=None,
        max_fee=0,
    ) -> Tuple[int, TransactionExecutionInfo]:
        state = account.state

        if nonce is None:
            nonce = await state.state.get_nonce_at(
                contract_address=account.contract_address
            )

        contract_class = get_contract_class(contract_name)
        class_hash = get_class_hash(contract_name)

        transaction_hash = get_transaction_hash(
            prefix=TransactionHashPrefix.DECLARE,
            account=account.contract_address,
            calldata=[class_hash],
            nonce=nonce,
            version=TRANSACTION_VERSION,
            max_fee=max_fee,
            chain_id=StarknetChainId.TESTNET.value,
        )

        signature = self.sign(transaction_hash)

        tx = InternalDeclare.create(
            sender_address=account.contract_address,
            contract_class=contract_class,
            chain_id=StarknetChainId.TESTNET.value,
            max_fee=max_fee,
            version=TRANSACTION_VERSION,
            nonce=nonce,
            signature=signature,
        )

        execution_info = await state.execute_tx(tx=tx)

        await state.state.set_contract_class(
            class_hash=tx.class_hash, contract_class=contract_class
        )
        return class_hash, execution_info

    async def deploy_account(
        self,
        state,
        calldata,
        salt=0,
        nonce=0,
        max_fee=0,
    ) -> TransactionExecutionInfo:
        account_address = calculate_contract_address_from_hash(
            salt=salt,
            class_hash=self.class_hash,
            constructor_calldata=calldata,
            deployer_address=0,
        )

        transaction_hash = get_transaction_hash(
            prefix=TransactionHashPrefix.DEPLOY_ACCOUNT,
            account=account_address,
            calldata=[self.class_hash, salt, *calldata],
            nonce=nonce,
            version=TRANSACTION_VERSION,
            max_fee=max_fee,
            chain_id=StarknetChainId.TESTNET.value,
        )

        signature = self.sign(transaction_hash)

        external_tx = DeployAccount(
            class_hash=self.class_hash,
            contract_address_salt=salt,
            constructor_calldata=calldata,
            signature=signature,
            max_fee=max_fee,
            version=TRANSACTION_VERSION,
            nonce=nonce,
        )

        tx = InternalTransaction.from_external(
            external_tx=external_tx, general_config=state.general_config
        )

        execution_info = await state.execute_tx(tx=tx)
        return execution_info


class MockSigner(BaseSigner):
    """
    Utility for sending signed transactions to an Account on Starknet.

    Parameters
    ----------

    private_key : int

    Examples
    ---------
    Constructing a MockSigner object

    >>> signer = MockSigner(1234)

    Sending a transaction

    >>> await signer.send_transaction(
            account, contract_address, 'contract_method', [arg_1]
        )

    Sending multiple transactions

    >>> await signer.send_transactions(
            account, [
                (contract_address, 'contract_method', [arg_1]),
                (contract_address, 'another_method', [arg_1, arg_2])
            ]
        )

    """

    def __init__(self, private_key):
        self.signer = Signer(private_key)
        self.public_key = self.signer.public_key
        self.class_hash = get_class_hash("Account")

    def sign(self, transaction_hash):
        sig_r, sig_s = self.signer.sign(transaction_hash)
        return [sig_r, sig_s]


def get_raw_invoke(sender: StarknetContract, calls):
    """Return raw invoke, remove when test framework supports `invoke`."""
    call_array, calldata = from_call_to_call_array(calls)
    raw_invocation = sender.__execute__(call_array, calldata)
    return raw_invocation
