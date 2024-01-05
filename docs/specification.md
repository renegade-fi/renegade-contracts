# Renegade Contracts Specification

## Contract Topology

The on-chain portion of the Renegade protocol is comprised of a system of 6 contracts.
They are as follows:
1. `TransparentUpgradeableProxy`
2. `ProxyAdmin`
3. `DarkpoolContract`
4. `MerkleContract`
5. `VerifierContract`
6. `VkeysContract`

1 & 2 are not implemented by Renegade, rather we directly deployed `v5.0` of OpenZeppelin's `TransparentUpgradeableProxy` contract, which itself deploys a `ProxyAdmin`. Details about these contracts and the transparent upgradeable proxy pattern can be found [here](https://docs.openzeppelin.com/contracts/5.x/api/proxy#transparent_proxy).

The remaining contracts are interacted with only by the `DarkpoolContract`, which serves as the sole user-facing entrypoint to the protocol.

## Basic Contract Functionality

The following is brief overview of the functioning of the on-chain portion of the Renegade protocol. This assumes familiarity with the broader Renegade protocol, for which we'd recommend reading the [whitepaper](https://www.renegade.fi/whitepaper.pdf) or the [docs](https://docs.renegade.fi/).

The Renegade contracts manage deposits / withdrawals of users' funds into / from the darkpool, track commitments to current and nullified user wallets, and handle the settlement of trades. 

Users submit changes to their wallet (e.g., creating a new wallet, creating / cancelling orders, settling matched trades) to the `DarkpoolContract`.

These changes are encapsulated in a [Plonk](https://eprint.iacr.org/2019/953.pdf) zero-knowledge proof(s), which the `DarkpoolContract` verifies by `staticcall`ing the `VerifierContract` (during this process, the `DarkpoolContract` also `staticcall`s the `VkeysContract` for preprocessed public information about the statement being proven).

If the change was the settlement of a matched trade, then the `DarkpoolContract` also verifies "proof linking" between the Plonk proofs involved - this is a cryptographic statement attesting that the Plonk proofs use the same public inputs where appropriate. This, too is, done via a `staticcall` to the `VerifierContract` (and also fetches preprocessed information from the `VkeysContract`).

The updated wallet is committed to as a leaf in a global Merkle tree via a `delegatecall` to the `MerkleContract` from the `DarkpoolContract`. We also add the newly-computed root to a set of historic roots.

If the change was an update to an existing wallet by the user (this excludes the settlement of a matched trade, which can be done by a relayer), we also verify an ECDSA signature by the user over the commitment to the updated wallet to be inserted into the Merkle tree.

The old wallet is then "nullified" in the `DarkpoolContract`, preventing it from being considered valid (we call such a wallet "spent"). This is done by having the user reveal the old wallet's "nullifier", an initially private value associated with a given state of a wallet.

If the change was a deposit / withdrawal of a certain asset to / from a user's wallet, the `DarkpoolContract` also executes an ERC-20 transfer of the asset between itself and the user, in the appropriate direction. 

## Contract State

All of the state in the on-chain portion of the Renegade protocol is held in one contract, the `TransparentUpgradeableProxy`, since this contract proxies all calls to the `DarkpoolContract` via `delegatecall`, and the `DarkpoolContract` also calls the other contracts using only `delegatecall` or `staticcall`.

For all intents and purposes though, one can think of the `DarkpoolContract` as managing all of the state.

The high-level state elements are the following:
- Merkle tree
    - A height-32 (exclusive of the root) Merkle tree that uses the [Poseidon 2](https://eprint.iacr.org/2023/323.pdf) hash function[^1] over elements of the BN254 curve's scalar field.
    - The leaves inserted into the tree are Poseidon 2 hash commitments to users' wallets
    - We also store the set of all historical roots of the tree.
- Nullifier set
    - The set of all spent wallet nullifiers
- Verification keys
    - Preprocessed information for the Plonk circuits & proof linking statements being proven[^2]
- Contract addresses
    - The `DarkpoolContract` must know the addresses for the `MerkleContract`, `VerifierContract`, and aforementioned `VkeysContract` so that it can `delegatecall` / `staticcall` them appropriately

## Contract Interfaces

Let's take a closer, detailed look at the contract functionality. The following is an overview of each of the contracts' external interfaces:

`DarkpoolContract`:
- `initialize`
    - Initializes the smart contract system, storing the contract addresses needed by the `DarkpoolContract` (described above), and instantiating an empty Merkle tree by `delegatecall`ing the `MerkleContract`. Intended to be called by the `ProxyAdmin` as a nested call of the `upgradeToAndCall` method.
- `is_nullifier_spent`
    - Checks whether the passed-in nullifier is present in the set maintained by the contract (i.e., if the wallet associated with this nullifier is spent).
- `get_root`
    - Returns the current root of the Merkle tree by `delegatecall`ing the `MerkleContract`.
- `root_in_history`
    - Checks whether or not the passed-in candidate Merkle root is a valid historical root by `delegatecall`ing the `MerkleContract`.
- `new_wallet`
    - Adds a new wallet to the protocol state. This includes:
        1. Fetching the verification key for the `VALID WALLET CREATE` statement by `staticcall`ing the `VkeysContract`
        2. Verifying a Plonk proof of the `VALID WALLET CREATE` statement by `staticcall`ing the `VerifierContract`
        3. Inserting the commitment to the new wallet's state into the Merkle tree by `delegatecall`ing the `MerkleContract`
        4. Emitting a `WalletUpdated` event with a public identifier of the new wallet
- `update_wallet`
    - Updates an existing wallet, e.g. depositing / withdrawing funds to / from the wallet, or creating / cancelling an order. This includes:
        1. Asserting that the Merkle root included in the passed-in Plonk proof of `VALID WALLET UPDATE` is a valid historical root
        2. Fetching the verification key for the `VALID WALLET UPDATE` statement by `staticcall`ing the `VkeysContract`
        3. Verifying a Plonk proof of the `VALID WALLET UPDATE` statement by `staticcall`ing the `VerifierContract`
        4. Verifying an ECDSA signature over the commitment to the wallet's state
        5. Inserting a commitment to the wallet's state into the Merkle tree by `delegatecall`ing the `MerkleContract`
        6. Marking the old wallet's nullifier as spent
        7. If the update was a deposit / withdrawal of an ERC20 asset, executing an ERC20 transfer for the asset between the user & contract in the appropriate direction
        8. Emitting a `WalletUpdated` event with a public identifier of the wallet
- `process_match_settle`
    - Settles a matched trade between two wallets. This includes:
        1. Asserting that the Merkle roots inlcuded in the passed-in Plonk proofs of `VALID REBLIND` for each party are valid historical roots
        2. Fetching the verification keys for `VALID REBLIND`, `VALID COMMITMENTS`, & `VALID MATCH SETTLE`, alongside the proof-linking verirication keys for the `VALID REBLIND <-> VALID COMMITMENTS`, `PARTY 0 VALID COMMITMENTS <-> VALID MATCH SETTLE`, & `PARTY 1 VALID COMMITMENTS <-> VALID MATCH SETTLE` links by `staticcall`ing the `VkeysContract`
        3. Batch-verifying Plonk proofs of the `VALID REBLIND` & `VALID COMMITMENTS` statements for both parties, and a proof of `VALID MATCH SETTLE`, by `staticcall`ing the `VerifierContract`
        4. Batch-verifying linking proofs of the `VALID REBLIND <-> VALID COMMITMENTS`, `PARTY 0 VALID COMMITMENTS <-> VALID MATCH SETTLE`, & `PARTY 1 VALID COMMITMENTS <-> VALID MATCH SETTLE` links by `staticcall`ing the `VerifierContract`
        5. Inserting commitments to each party's post-trade wallets into the Merkle tree by `delegatecall`ing the `MerkleContract`
        6. Marking each party's old wallet's nullifier as spent

`MerkleContract`
- `init`
    - Initializes an empty Merkle tree
- `root`
    - Returns the current Merkle root
- `root_in_history`
    - Checks whether the passed-in candidate Merkle root is a valid historical root
- `insert_shares_commitment`
    - Computes a commitment to the passed-in wallet and inserts it as a leaf into the Merkle tree
- `verify_state_sig_and_insert`
    - Computes a commitment to the passed-in wallet, verifies a user-generated ECDSA signature over it (this includes a `staticcall` to the [`ecRecover` precompile](https://www.evm.codes/precompiled#0x01?fork=shanghai)), and inserts it into the Merkle tree

`VerifierContract`
- `verify`
    - Verifies the passed-in Plonk proof. This incurs many `staticcall`s to the [`ecAdd`](https://www.evm.codes/precompiled#0x06?fork=shanghai) and [`ecMul` precompiles](https://www.evm.codes/precompiled#0x07?fork=shanghai), and a single `staticcall` to the [`ecPairing` precompile](https://www.evm.codes/precompiled#0x08?fork=shanghai)
- `verify_match`
    - Batch-verifies the passed-in Plonk & linking proofs together. This is only intended to be called by the `DarkpoolContract`'s `process_match_settle` method, in that it expects the same proofs as that method does. This, too, incurs many `staticcall`s to the `ecAdd` and `ecMul` precompiles, and a single `staticcall` to `ecPairing`

## Assumptions

We make the following assumptions about interaction with the protocol:
- We deploy the contracts correctly (e.g. Merkle tree is correct height, verification keys are correct)
- The `ProxyAdmin` is initialized with an owner account that we securely control
- The `initialize` method of the `DarkpoolContract` is called in the deployment of the `TransparentUpgradeableProxy`
- Management of a wallet is only delegated to a single cluster
- Calldata is generally available for wallet indexing & recovery

## Protocol Invariants

The following invariants must hold true in all possible states of the protocol. They are phrased abstractly, agnostic of the contract topology & implementation, to maintain the proper scope & be future-proof.

### Darkpool product invariants

- The darkpool can only be initialized during initial deployment or upgrade
- The logic for wallet state transition validity & global state commitments can only be set during darkpool initialization
- The darkpool rejects malformed inputs instead of coercing them into an operable form
- Spent wallets can't be updated in any way, including settling orders they contain
- Wallets can only be spent by being updated (e.g. modifying orders / fees, depositing / withdrawing), or having one of their orders matched & settled
- In the case of a deposit / withdrawal, only the user & darkpool's asset balances are affected, and only by the amount expected in the deposit / withdrawal[^3]
- The darkpool executes an asset transfer only in the event of a valid deposit / withdrawal

### Global state commitment invariants

- The global state commitment can only be mutated during darkpool initialization, or the successful creation / updating of a wallet
- During the successful creation / updating of a wallet, the only mutation of the global state commitment is committing to that wallet
- All valid global state commitments (and nothing else) are tracked as historic global state commitments
- Only wallets authorized by the user should be committed to in the global state commitment
- Commitments within the global state commitment cannot be overwritten

### Wallet state transition validity invariants

- All valid wallet state transitions are approved
- All invalid wallet state transitions are rejected

[^1]: The constants for our instantiation of the Poseidon 2 hash can be found [here](https://github.com/renegade-fi/renegade/blob/main/renegade-crypto/src/hash/constants.rs)

[^2]: These are hardcoded as contract code in the `VkeysContract` to minimize storage costs

[^3]:

    This invariant is technically outside of our control, as it depends on the ERC20's transfer implementation.

    While it's not safe to state an assumption along the lines of, "any ERC20s in the darkpool do not have transfer side effects outside of incrementing/decrementing sender/recipient balances", we should still constrain this as much as possible - e.g., we should be sure our contracts are reentrant-safe.
    
    With that said, it does mean some ERC20s can get "stuck" in our darkpool. Imagine, for example, an ERC20 that takes a "tax" on all transfers. Withdrawing some of it from your wallet's balances will make future updates fail Plonk verification...
