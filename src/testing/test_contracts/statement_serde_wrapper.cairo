use traits::Into;
use array::ArrayTrait;

use renegade_contracts::{
    darkpool::{
        statements::{
            ValidWalletCreateStatement, ValidWalletUpdateStatement, ValidReblindStatement,
            ValidCommitmentsStatement, ValidSettleStatement
        },
        types::PublicSigningKey
    },
    verifier::scalar::Scalar
};


const MAX_BALANCES: usize = 2;
const MAX_ORDERS: usize = 2;
const MAX_FEES: usize = 1;

const DUMMY_VALUE: u64 = 42;


#[starknet::interface]
trait IStatementSerde<TContractState> {
    fn assert_valid_wallet_create_statement(
        self: @TContractState, statement: ValidWalletCreateStatement
    );
    fn assert_valid_wallet_update_statement(
        self: @TContractState, statement: ValidWalletUpdateStatement
    );
    fn assert_valid_reblind_statement(self: @TContractState, statement: ValidReblindStatement);
    fn assert_valid_commitments_statement(
        self: @TContractState, statement: ValidCommitmentsStatement
    );
    fn assert_valid_settle_statement(self: @TContractState, statement: ValidSettleStatement);
    fn assert_valid_wallet_create_statement_to_scalars(
        self: @TContractState, statement_scalars: Array<Scalar>
    );
    fn assert_valid_wallet_update_statement_to_scalars(
        self: @TContractState, statement_scalars: Array<Scalar>
    );
    fn assert_valid_reblind_statement_to_scalars(
        self: @TContractState, statement_scalars: Array<Scalar>
    );
    fn assert_valid_commitments_statement_to_scalars(
        self: @TContractState, statement_scalars: Array<Scalar>
    );
    fn assert_valid_settle_statement_to_scalars(
        self: @TContractState, statement_scalars: Array<Scalar>
    );
}

#[starknet::contract]
mod StatementSerdeWrapper {
    use renegade_contracts::{
        darkpool::statements::{
            ValidWalletCreateStatement, ValidWalletUpdateStatement, ValidReblindStatement,
            ValidCommitmentsStatement, ValidSettleStatement
        },
        verifier::scalar::{Scalar, ScalarSerializable}, utils::eq::ArrayTPartialEq
    };

    use super::{
        dummy_valid_wallet_create_statement, dummy_valid_wallet_update_statement,
        dummy_valid_reblind_statement, dummy_valid_commitments_statement,
        dummy_valid_settle_statement,
    };

    #[storage]
    struct Storage {}

    #[external(v0)]
    impl StatementSerdeWrapperImpl of super::IStatementSerde<ContractState> {
        fn assert_valid_wallet_create_statement(
            self: @ContractState, statement: ValidWalletCreateStatement
        ) {
            assert(
                statement == dummy_valid_wallet_create_statement(), 'VALID_WALLET_CREATE: statement'
            )
        }

        fn assert_valid_wallet_update_statement(
            self: @ContractState, statement: ValidWalletUpdateStatement
        ) {
            assert(
                statement == dummy_valid_wallet_update_statement(), 'VALID_WALLET_UPDATE: statement'
            )
        }

        fn assert_valid_reblind_statement(self: @ContractState, statement: ValidReblindStatement) {
            assert(statement == dummy_valid_reblind_statement(), 'VALID_REBLIND: statement')
        }

        fn assert_valid_commitments_statement(
            self: @ContractState, statement: ValidCommitmentsStatement
        ) {
            assert(statement == dummy_valid_commitments_statement(), 'VALID_COMMITMENTS: statement')
        }

        fn assert_valid_settle_statement(self: @ContractState, statement: ValidSettleStatement) {
            assert(statement == dummy_valid_settle_statement(), 'VALID_SETTLE: statement')
        }

        fn assert_valid_wallet_create_statement_to_scalars(
            self: @ContractState, statement_scalars: Array<Scalar>
        ) {
            assert(
                statement_scalars == dummy_valid_wallet_create_statement().to_scalars(),
                'VALID_WALLET_CREATE: scalar ser'
            )
        }

        fn assert_valid_wallet_update_statement_to_scalars(
            self: @ContractState, statement_scalars: Array<Scalar>
        ) {
            assert(
                statement_scalars == dummy_valid_wallet_update_statement().to_scalars(),
                'VALID_WALLET_UPDATE: scalar ser'
            )
        }

        fn assert_valid_reblind_statement_to_scalars(
            self: @ContractState, statement_scalars: Array<Scalar>
        ) {
            assert(
                statement_scalars == dummy_valid_reblind_statement().to_scalars(),
                'VALID_REBLIND: scalar ser'
            )
        }

        fn assert_valid_commitments_statement_to_scalars(
            self: @ContractState, statement_scalars: Array<Scalar>
        ) {
            assert(
                statement_scalars == dummy_valid_commitments_statement().to_scalars(),
                'VALID_COMMITMENTS: scalar ser'
            )
        }

        fn assert_valid_settle_statement_to_scalars(
            self: @ContractState, statement_scalars: Array<Scalar>
        ) {
            assert(
                statement_scalars == dummy_valid_settle_statement().to_scalars(),
                'VALID_SETTLE: scalar ser'
            )
        }
    }
}

// --------------------
// | DUMMY STATEMENTS |
// --------------------

fn dummy_valid_wallet_create_statement() -> ValidWalletCreateStatement {
    ValidWalletCreateStatement {
        private_shares_commitment: DUMMY_VALUE.into(),
        public_wallet_shares: dummy_public_wallet_shares(),
    }
}

fn dummy_valid_wallet_update_statement() -> ValidWalletUpdateStatement {
    ValidWalletUpdateStatement {
        old_shares_nullifier: DUMMY_VALUE.into(),
        new_private_shares_commitment: DUMMY_VALUE.into(),
        new_public_shares: dummy_public_wallet_shares(),
        merkle_root: DUMMY_VALUE.into(),
        external_transfer: Default::default(),
        old_pk_root: dummy_public_signing_key(),
        timestamp: DUMMY_VALUE,
    }
}

fn dummy_valid_reblind_statement() -> ValidReblindStatement {
    ValidReblindStatement {
        original_shares_nullifier: DUMMY_VALUE.into(),
        reblinded_private_shares_commitment: DUMMY_VALUE.into(),
        merkle_root: DUMMY_VALUE.into(),
    }
}

fn dummy_valid_commitments_statement() -> ValidCommitmentsStatement {
    ValidCommitmentsStatement {
        balance_send_index: DUMMY_VALUE,
        balance_receive_index: DUMMY_VALUE,
        order_index: DUMMY_VALUE,
    }
}

fn dummy_valid_settle_statement() -> ValidSettleStatement {
    ValidSettleStatement {
        party0_modified_shares: dummy_public_wallet_shares(),
        party1_modified_shares: dummy_public_wallet_shares(),
        party0_send_balance_index: DUMMY_VALUE,
        party0_receive_balance_index: DUMMY_VALUE,
        party0_order_index: DUMMY_VALUE,
        party1_send_balance_index: DUMMY_VALUE,
        party1_receive_balance_index: DUMMY_VALUE,
        party1_order_index: DUMMY_VALUE,
    }
}

// ---------------------------
// | DUMMY STATEMENT HELPERS |
// ---------------------------

fn dummy_public_wallet_shares() -> Array<Scalar> {
    let mut public_wallet_shares = ArrayTrait::new();
    let mut i = 0;
    loop {
        // Number of shares is:
        //   2 * MAX_BALANCES (amount, mint)
        // + 6 * MAX_ORDERS (quote_mint, base_mint, side, amount, worst_case_price, timestamp)
        // + 4 * MAX_FEES (settle_key, gas_addr, gas_token_amount, percentage_fee)
        // + 2 (for the public signing key)
        // + 1 (for the public identification key)
        // + 1 (for the blinder)
        if i == 2 * MAX_BALANCES + 6 * MAX_ORDERS + 4 * MAX_FEES + 4 {
            break;
        };
        public_wallet_shares.append(DUMMY_VALUE.into());
        i += 1;
    };

    public_wallet_shares
}

fn dummy_public_signing_key() -> PublicSigningKey {
    // Public signing key coordinates are represented by 2 scalars

    let mut x = ArrayTrait::new();

    x.append(DUMMY_VALUE.into());
    x.append(DUMMY_VALUE.into());

    let mut y = ArrayTrait::new();

    y.append(DUMMY_VALUE.into());
    y.append(DUMMY_VALUE.into());

    PublicSigningKey { x, y }
}
