//! Integration tests for the contracts

mod admin;
mod atomic_settlement;
mod basic_darkpool_interaction;
mod darkpool_components;
mod external_transfer;
mod fees;
mod gas_sponsorship;
mod precompile;

// TODO: Add test cases covering invalid historical Merkle roots,
// invalid signatures over wallet commitments, and duplicate nullifiers
