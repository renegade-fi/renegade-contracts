# Renegade Contracts Specification

## Contract Topology

The on-chain portion of the Renegade protocol is comprised of a system of 6 contracts.
They are as follows:
1. `TransparentUpgradeableProxy`
2. `ProxyAdmin`
3. `DarkpoolContract`
4. `DarkpoolCoreContract`
5. `MerkleContract`
6. `VerifierContract`
7. `VkeysContract`
8. `TransferExecutorContract`

1 & 2 are not implemented by Renegade, rather we directly deployed `v5.0` of OpenZeppelin's `TransparentUpgradeableProxy` contract, which itself deploys a `ProxyAdmin`. Details about these contracts and the transparent upgradeable proxy pattern can be found [here](https://docs.openzeppelin.com/contracts/5.x/api/proxy#transparent_proxy). Additionally, the protocol assumes the existence of a deployed `Permit2` contract. Details about `Permit2` can be found [here](https://docs.uniswap.org/contracts/permit2/overview).

The remaining contracts are interacted with only by the `DarkpoolContract`, which serves as the sole user-facing entrypoint to the protocol. The reason we have this many contracts, then, is due to constraints on the binary size of a deployed contract (24kb, Brotli-compressed).

## Basic Contract Functionality

The following is brief overview of the functioning of the on-chain portion of the Renegade protocol. This assumes familiarity with the broader Renegade protocol, for which we'd recommend reading the [whitepaper](https://www.renegade.fi/whitepaper.pdf) or the [docs](https://docs.renegade.fi/).

The Renegade contracts manage deposits / withdrawals of users' funds into / from the darkpool, track commitments to current and nullified user wallets, and handle the settlement of trades and fee payments.

The `DarkpoolContract` is responsible for managing access controls and system parameters, and serving externally-facing getter methods. Otherwise, it `delegatecall`s the `DarkpoolCoreContract` to handle all wallet-mutating methods (e.g., creating a new wallet, creating / cancelling orders, settling matched trades).

These changes are encapsulated in [Plonk](https://eprint.iacr.org/2019/953.pdf) zero-knowledge proofs, which the `DarkpoolCoreContract` verifies by `staticcall`ing the `VerifierContract` (during this process, the `DarkpoolContract` also `staticcall`s the `VkeysContract` for preprocessed public information about the statement being proven).

If the change was the settlement of a matched trade, then the `DarkpoolCoreContract` also verifies "proof linking" between the Plonk proofs involved - this is a cryptographic statement attesting that the Plonk proofs use the same public inputs where appropriate. This, too is, done via a `staticcall` to the `VerifierContract` (and also fetches preprocessed information from the `VkeysContract`).

The updated wallet is committed to as a leaf in a global Merkle tree via a `delegatecall` to the `MerkleContract` from the `DarkpoolCoreContract`. We also add the newly-computed root to a set of historic roots.

In some cases of wallet changes, namely when the wallet is not constrained in-circuit to be properly reblinded, the wallet owner must also sign a commitment to the updated wallet. This is a secp256k1 ECDSA signature made using the user's `sk_root` that we verify before committing the wallet to the Merkle tree.

The old wallet is then "nullified" in the `DarkpoolCoreContract`, preventing it from being considered valid (we call such a wallet "spent"). This is done by having the user reveal the old wallet's "nullifier", an initially private value associated with a given state of a wallet.

If the change was a deposit / withdrawal of a certain asset to / from a user's wallet, the `DarkpoolCoreContract` also executes an ERC-20 transfer of the asset between itself and the user, in the appropriate direction. This is done by `delegatecall`ing the `TransferExecutorContract`, which executes deposits through the `Permit2` contract, and checks a user signature over the transfer metadata in the case of withdrawals.

A more in-depth explanation of the contracts' functionality can be found in doc comments throughout the [contract definitions](../contracts-stylus/src/contracts).

## Contract State

All of the state in the on-chain portion of the Renegade protocol is held in one contract, the `TransparentUpgradeableProxy`, since this contract proxies all calls to the `DarkpoolContract` via `delegatecall`, and the `DarkpoolContract` also calls the other contracts using only `delegatecall` or `staticcall` (excluding, of course, the `call`s made to `Permit2` / ERC-20 contracts for deposits and withdrawals).

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
- Protocol fee
    - A global parameter indicating the fee taken by the protocol. This is a fixed percentage of each trade's volume represented as a fixed-point number with a 32-bit fractional portion
- Protocol public encryption key
    - The EC-ElGamal public encryption key, over the BabyJubJub curve, to which fee notes owed to the protocol are encrypted
- Contract addresses
    - The `DarkpoolContract` must know the following contract addresses in order to `delegatecall` / `staticcall` them appropriately:
        - `DarkpoolCoreContract`
        - `VerifierContract`
        - `VkeysContract`
        - `MerkleContract`
        - `TransferExecutorContract`

## Access Controls

The on-chain protocol has the following access controls securing it:
- Initialization
    - The `DarkpoolContract` can only be initialized to a given version number once, ensuring that initialization logic is only ever executed during deployment or an upgrade. This follows from OpenZeppelin's `Initializable` [pattern](https://docs.openzeppelin.com/contracts/5.x/api/proxy#Initializable).
- Upgradeability
    - We use OpenZeppelin's transparent upgradeable proxy pattern, as mentioned above. As such, the `DarkpoolContract` has all calls proxied to it through the `TransparentUpgradeableProxy` via a `delegatecall`, and can be upgraded via the `ProxyAdmin`.
        - In using the OpenZeppelin contract implementations, we also adopt their access controls for the `TransparentUpgradeableProxy` and `ProxyAdmin`. Namely, the `ProxyAdmin` has a dedicated owner that can call its upgrade method, and the `TransparentUpgradeableProxy` only accepts upgrade calls from the `ProxyAdmin`.
    - Separately from the high-level transparent upgradeable proxy pattern being used for managing the version of the `DarkpoolContract`, we have individual, access-controlled methods defined on the `DarkpoolContract` for upgrading the implementations of the `DarkpoolCoreContract`, `VerifierContract`, `VkeysContract`, `MerkleContract`, and `TransferExecutorContract`.
        - This allows us to scope individual upgrades to these components, without requiring upgrades to the entire `DarkpoolContract`. However, an upgrade to the `DarkpoolCoreContract` will likely have to be coupled with an upgrade to the `DarkpoolContract`, and vice versa, since they must mirror one another's storage layout perfectly. For more information, see the `DarkpoolCoreContract` [module](../contracts-stylus/src/contracts/darkpool_core.rs).
- Ownership
    - The `DarkpoolContract` has a dedicated owner, potentially separate from the owner of the `ProxyAdmin`. This owner can be set during initialization, or ownership can be transferred from the current owner to another.
    - Only the `DarkpoolContract` owner can call certain protected setter methods, such as setting the protocol fee, pausing the contract, or upgrading implementations of the other contracts.
- Pausing
    - The `DarkpoolContract` can be paused, meaning that any user-accessible, state mutating methods (i.e., those that are not scoped to just the contract owner) will revert.
    - This is meant as an emergency measure, to give us time to upgrade any faulty or compromised implementations in the case of an attack or other unintended contract functionality.

## Assumptions

We make the following assumptions about interaction with the protocol:
- We deploy the contracts correctly (e.g. Merkle tree is correct height, verification keys are correct)
- The `ProxyAdmin` is initialized with an owner account that we securely control
- The `initialize` method of the `DarkpoolContract` is called in the deployment of the `TransparentUpgradeableProxy`
- Management of a wallet is only delegated to a single cluster
- Calldata is generally available for wallet indexing & recovery
- A `Permit2` contract is deployed

## Protocol Invariants

The following invariants must hold true in all possible states of the protocol. They are phrased abstractly, agnostic of the contract topology & implementation, to maintain the proper scope & be future-proof.

### Darkpool product invariants

- The darkpool contract is the sole entrypoint to any methods that may alter the on-chain protocol's state
- The darkpool can only be initialized during initial deployment or upgrade
- The logic for wallet state transition validity & global state commitments can only be set by the darkpool contract owner
- Global parameters can only be set by the darkpool contract owner
- Any state-mutating methods that can be called by users other than the darkpool contract owner can only be called when the contract is unpaused
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
