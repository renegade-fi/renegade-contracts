//! Implementations of the various deploy scripts

use alloy::{
    network::TransactionBuilder,
    primitives::{Address, Bytes, U256},
    providers::Provider,
    rpc::types::TransactionRequest,
};
use alloy_sol_types::SolConstructor;
use circuit_types::traits::SingleProverCircuit;
use circuits::zk_circuits::{
    valid_commitments::SizedValidCommitments,
    valid_fee_redemption::SizedValidFeeRedemption,
    valid_malleable_match_settle_atomic::SizedValidMalleableMatchSettleAtomic,
    valid_match_settle::{SizedValidMatchSettle, SizedValidMatchSettleWithCommitments},
    valid_match_settle_atomic::{
        SizedValidMatchSettleAtomic, SizedValidMatchSettleAtomicWithCommitments,
    },
    valid_offline_fee_settlement::SizedValidOfflineFeeSettlement,
    valid_reblind::SizedValidReblind,
    valid_relayer_fee_settlement::SizedValidRelayerFeeSettlement,
    valid_wallet_create::SizedValidWalletCreate,
    valid_wallet_update::SizedValidWalletUpdate,
};
use contracts_utils::{
    conversion::to_contract_vkey,
    proof_system::{
        dummy_renegade_circuits::{
            DummyValidCommitments, DummyValidFeeRedemption, DummyValidMalleableMatchSettleAtomic,
            DummyValidMatchSettle, DummyValidMatchSettleAtomic,
            DummyValidMatchSettleAtomicWithCommitments, DummyValidMatchSettleWithCommitments,
            DummyValidOfflineFeeSettlement, DummyValidReblind, DummyValidRelayerFeeSettlement,
            DummyValidWalletCreate, DummyValidWalletUpdate,
        },
        gen_malleable_match_atomic_linking_vkeys, gen_malleable_match_atomic_vkeys,
        gen_match_atomic_linking_vkeys, gen_match_atomic_vkeys, gen_match_linking_vkeys,
        gen_match_vkeys,
    },
};
use hex::FromHex;
use rand::{thread_rng, Rng};
use std::{env, str::FromStr};
use tracing::log::info;
use util::err_str;

use crate::{
    cli::{
        DeployDarkpoolProxyArgs, DeployErc20Args, DeployGasSponsorProxyArgs, DeployStylusArgs,
        DeployTestContractsArgs, GenVkeysArgs, SetAllDelegateAddressesCalldataArgs, UpgradeArgs,
    },
    constants::{
        TransparentUpgradeableProxy, NUM_BYTES_ADDRESS, NUM_BYTES_STORAGE_SLOT, PERMIT2_BYTECODE,
        PERMIT2_CONTRACT_KEY, PROCESS_MALLEABLE_MATCH_SETTLE_ATOMIC_VKEYS_FILE,
        PROCESS_MATCH_SETTLE_ATOMIC_VKEYS_FILE,
        PROCESS_MATCH_SETTLE_ATOMIC_WITH_COMMITMENTS_VKEYS_FILE, PROCESS_MATCH_SETTLE_VKEYS_FILE,
        PROCESS_MATCH_SETTLE_WITH_COMMITMENTS_VKEYS_FILE, PROXY_ADMIN_CONTRACT_KEY,
        PROXY_ADMIN_STORAGE_SLOT, PROXY_CONTRACT_KEY, TEST_ERC20_DECIMALS, TEST_ERC20_TICKER1,
        TEST_ERC20_TICKER2, TEST_FUNDING_AMOUNT, TRANSPARENT_UPGRADEABLE_PROXY_BYTECODE,
        VALID_FEE_REDEMPTION_VKEY_FILE, VALID_OFFLINE_FEE_SETTLEMENT_VKEY_FILE,
        VALID_RELAYER_FEE_SETTLEMENT_VKEY_FILE, VALID_WALLET_CREATE_VKEY_FILE,
        VALID_WALLET_UPDATE_VKEY_FILE,
    },
    errors::ScriptError,
    solidity::{DummyErc20, DummyWeth, ProxyAdmin},
    types::{RenegadeVerificationKeys, StylusContract},
    utils::{
        build_stylus_contract, darkpool_initialize_calldata, deploy_stylus_contract,
        gas_sponsor_initialize_calldata, get_protocol_external_fee_collection_address,
        get_public_encryption_key, read_deployment_address, read_stylus_deployment_address,
        send_raw_tx, send_tx, set_all_delegate_addresses_calldata, setup_client,
        write_deployment_address, write_stylus_contract_address, write_vkey_file,
        LocalWalletHttpClient,
    },
};

/// The amount of wei to fund a wrapper contract with
const WRAPPER_FUNDING_AMOUNT: u64 = 1_000_000;

/// Builds & deploys all of the contracts necessary for running the integration
/// testing suite.
///
/// This includes generating fresh verification keys for testing.
pub async fn deploy_test_contracts(
    args: &DeployTestContractsArgs,
    rpc_url: &str,
    priv_key: &str,
    client: LocalWalletHttpClient,
    deployments_path: &str,
) -> Result<(), ScriptError> {
    info!("Generating testing verification keys");
    let gen_vkeys_args = GenVkeysArgs { vkeys_dir: args.vkeys_dir.clone(), test: true };
    gen_vkeys(&gen_vkeys_args)?;

    let mut deploy_stylus_args =
        DeployStylusArgs { contract: StylusContract::TestVkeys, no_verify: args.no_verify };

    info!("Deploying testing verification keys");
    build_and_deploy_stylus_contract(
        &deploy_stylus_args,
        rpc_url,
        priv_key,
        client.clone(),
        deployments_path,
    )
    .await?;

    // Deploy the auxiliary testing contracts.
    // We do this first because they use the same compiler flags,
    // so we make use of the cached build artifacts.

    info!("Deploying dummy upgrade target contract");
    deploy_stylus_args.contract = StylusContract::DummyUpgradeTarget;
    build_and_deploy_stylus_contract(
        &deploy_stylus_args,
        rpc_url,
        priv_key,
        client.clone(),
        deployments_path,
    )
    .await?;

    info!("Deploying precompiles testing contract");
    deploy_stylus_args.contract = StylusContract::PrecompileTestContract;
    build_and_deploy_stylus_contract(
        &deploy_stylus_args,
        rpc_url,
        priv_key,
        client.clone(),
        deployments_path,
    )
    .await?;

    info!("Deploying Merkle testing contract");
    deploy_stylus_args.contract = StylusContract::MerkleTestContract;
    build_and_deploy_stylus_contract(
        &deploy_stylus_args,
        rpc_url,
        priv_key,
        client.clone(),
        deployments_path,
    )
    .await?;

    info!("Deploying Permit2 contract");
    deploy_permit2(client.clone(), deployments_path).await?;

    info!("Deploying test ERC-20 contracts");
    let mut deploy_erc20_args = DeployErc20Args {
        symbol: TEST_ERC20_TICKER1.to_string(),
        name: TEST_ERC20_TICKER1.to_string(),
        decimals: TEST_ERC20_DECIMALS,
        as_wrapper: true, // deploy the first erc20 as a wrapper
        funding_amount: Some(TEST_FUNDING_AMOUNT),
        account_skeys: vec![priv_key.to_string()],
    };
    let addr =
        deploy_erc20(&deploy_erc20_args, rpc_url, priv_key, client.clone(), deployments_path)
            .await?;

    // Set the WETH_ADDRESS environment variable to the deployed erc20
    let addr_str = format!("{addr:#x}");
    env::set_var("WETH_ADDRESS", addr_str.as_str());

    deploy_erc20_args.symbol = TEST_ERC20_TICKER2.to_string();
    deploy_erc20_args.name = TEST_ERC20_TICKER2.to_string();
    deploy_erc20_args.as_wrapper = false; // deploy the second erc20 as a normal erc20
    deploy_erc20(&deploy_erc20_args, rpc_url, priv_key, client.clone(), deployments_path).await?;

    info!("Deploying transfer executor contract");
    deploy_stylus_args.contract = StylusContract::TransferExecutor;
    build_and_deploy_stylus_contract(
        &deploy_stylus_args,
        rpc_url,
        priv_key,
        client.clone(),
        deployments_path,
    )
    .await?;

    info!("Deploying verifier contract");
    deploy_stylus_args.contract = StylusContract::VerifierCore;
    build_and_deploy_stylus_contract(
        &deploy_stylus_args,
        rpc_url,
        priv_key,
        client.clone(),
        deployments_path,
    )
    .await?;

    info!("Deploying verifier settlement contract");
    deploy_stylus_args.contract = StylusContract::VerifierSettlement;
    build_and_deploy_stylus_contract(
        &deploy_stylus_args,
        rpc_url,
        priv_key,
        client.clone(),
        deployments_path,
    )
    .await?;

    info!("Deploying core wallet operations contract");
    deploy_stylus_args.contract = StylusContract::CoreWalletOps;
    build_and_deploy_stylus_contract(
        &deploy_stylus_args,
        rpc_url,
        priv_key,
        client.clone(),
        deployments_path,
    )
    .await?;

    info!("Deploying core match settlement contract");
    deploy_stylus_args.contract = StylusContract::CoreMatchSettle;
    build_and_deploy_stylus_contract(
        &deploy_stylus_args,
        rpc_url,
        priv_key,
        client.clone(),
        deployments_path,
    )
    .await?;

    info!("Deploying core atomic match settlement contract");
    deploy_stylus_args.contract = StylusContract::CoreAtomicMatchSettle;
    build_and_deploy_stylus_contract(
        &deploy_stylus_args,
        rpc_url,
        priv_key,
        client.clone(),
        deployments_path,
    )
    .await?;

    info!("Deploying core malleable match settlement contract");
    deploy_stylus_args.contract = StylusContract::CoreMalleableMatchSettle;
    build_and_deploy_stylus_contract(
        &deploy_stylus_args,
        rpc_url,
        priv_key,
        client.clone(),
        deployments_path,
    )
    .await?;

    info!("Deploying darkpool testing contract");
    deploy_stylus_args.contract = StylusContract::DarkpoolTestContract;
    build_and_deploy_stylus_contract(
        &deploy_stylus_args,
        rpc_url,
        priv_key,
        client.clone(),
        deployments_path,
    )
    .await?;

    info!("Deploying darkpool proxy contract");
    let deploy_darkpool_proxy_args = DeployDarkpoolProxyArgs {
        fee: thread_rng().gen(),
        protocol_public_encryption_key: None,
        protocol_external_fee_collection_address: None,
        test: true,
    };
    deploy_darkpool_proxy(&deploy_darkpool_proxy_args, client.clone(), deployments_path).await?;

    info!("Deploying gas sponsor contract");
    deploy_stylus_args.contract = StylusContract::GasSponsor;
    build_and_deploy_stylus_contract(
        &deploy_stylus_args,
        rpc_url,
        priv_key,
        client.clone(),
        deployments_path,
    )
    .await?;

    info!("Deploying gas sponsor proxy contract");
    let deploy_gas_sponsor_proxy_args =
        DeployGasSponsorProxyArgs { auth_address: format!("{:#x}", client.address()) };
    deploy_gas_sponsor_proxy(&deploy_gas_sponsor_proxy_args, client, deployments_path).await?;

    Ok(())
}

/// Deploys the proxy & proxy admin contracts for the gas sponsor
pub async fn deploy_gas_sponsor_proxy(
    args: &DeployGasSponsorProxyArgs,
    client: LocalWalletHttpClient,
    deployments_path: &str,
) -> Result<(), ScriptError> {
    let gas_sponsor_address =
        read_stylus_deployment_address(deployments_path, &StylusContract::GasSponsor)?;

    // Construct gas sponsor calldata
    let darkpool_proxy_key = format!("{}_{}", StylusContract::Darkpool, PROXY_CONTRACT_KEY);
    let darkpool_proxy_address = read_deployment_address(deployments_path, &darkpool_proxy_key)?;
    let auth_address =
        Address::from_str(&args.auth_address).map_err(err_str!(ScriptError::InvalidArguments))?;

    let initialize_calldata =
        Bytes::from(gas_sponsor_initialize_calldata(darkpool_proxy_address, auth_address));

    deploy_proxy(
        client,
        gas_sponsor_address,
        initialize_calldata,
        &StylusContract::GasSponsor.to_string(),
        deployments_path,
    )
    .await
}

/// Deploys the proxy & proxy admin contracts for the darkpool
pub async fn deploy_darkpool_proxy(
    args: &DeployDarkpoolProxyArgs,
    client: LocalWalletHttpClient,
    deployments_path: &str,
) -> Result<(), ScriptError> {
    // Construct darkpool initialization calldata

    let darkpool_contract =
        if args.test { StylusContract::DarkpoolTestContract } else { StylusContract::Darkpool };
    let merkle_contract =
        if args.test { StylusContract::MerkleTestContract } else { StylusContract::Merkle };
    let vkeys_contract = if args.test { StylusContract::TestVkeys } else { StylusContract::Vkeys };

    let darkpool_address = read_stylus_deployment_address(deployments_path, &darkpool_contract)?;
    let core_wallet_ops_address =
        read_stylus_deployment_address(deployments_path, &StylusContract::CoreWalletOps)?;
    let core_match_settle_address =
        read_stylus_deployment_address(deployments_path, &StylusContract::CoreMatchSettle)?;
    let core_atomic_match_settle_address =
        read_stylus_deployment_address(deployments_path, &StylusContract::CoreAtomicMatchSettle)?;
    let core_malleable_match_settle_address = read_stylus_deployment_address(
        deployments_path,
        &StylusContract::CoreMalleableMatchSettle,
    )?;
    let merkle_address = read_stylus_deployment_address(deployments_path, &merkle_contract)?;
    let verifier_core_address =
        read_stylus_deployment_address(deployments_path, &StylusContract::VerifierCore)?;
    let verifier_settlement_address =
        read_stylus_deployment_address(deployments_path, &StylusContract::VerifierSettlement)?;

    let vkeys_address = read_stylus_deployment_address(deployments_path, &vkeys_contract)?;

    let transfer_executor_address =
        read_stylus_deployment_address(deployments_path, &StylusContract::TransferExecutor)?;

    let permit2_address = read_deployment_address(deployments_path, PERMIT2_CONTRACT_KEY)?;

    let protocol_fee = U256::from(args.fee);

    let protocol_public_encryption_key =
        get_public_encryption_key(args.protocol_public_encryption_key.clone())?;

    let protocol_external_fee_collection_address = get_protocol_external_fee_collection_address(
        args.protocol_external_fee_collection_address.clone(),
    )?;

    let initialize_calldata = Bytes::from(darkpool_initialize_calldata(
        core_wallet_ops_address,
        core_match_settle_address,
        core_atomic_match_settle_address,
        core_malleable_match_settle_address,
        verifier_core_address,
        verifier_settlement_address,
        vkeys_address,
        merkle_address,
        transfer_executor_address,
        permit2_address,
        protocol_fee,
        protocol_public_encryption_key,
        protocol_external_fee_collection_address,
    ));

    deploy_proxy(
        client,
        darkpool_address,
        initialize_calldata,
        &StylusContract::Darkpool.to_string(),
        deployments_path,
    )
    .await
}

/// Deploys the `TransparentUpgradeableProxy` and `ProxyAdmin` contracts for the
/// given implementation contract
async fn deploy_proxy(
    client: LocalWalletHttpClient,
    implementation_address: Address,
    initialization_calldata: Bytes,
    deployment_prefix: &str,
    deployments_path: &str,
) -> Result<(), ScriptError> {
    // Deploy proxy contract
    let owner_address = client.address();
    let deploy_code =
        get_proxy_deploy_code(implementation_address, owner_address, initialization_calldata)?;

    let proxy_address = deploy_from_bytecode(&client, deploy_code).await?;

    info!("Proxy contract deployed at address:\n\t{:#x}", proxy_address);

    // Get proxy admin contract address
    // This is the recommended way to get the proxy admin address:
    // https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.0.0/contracts/proxy/ERC1967/ERC1967Utils.sol#L104-L106
    let slot = U256::from_str(PROXY_ADMIN_STORAGE_SLOT).unwrap();
    let slot_value = client
        .provider()
        .get_storage_at(proxy_address, slot)
        .await
        .map_err(|e| ScriptError::ContractInteraction(e.to_string()))?;
    let addr_bytes = &slot_value.to_be_bytes_vec()
        [NUM_BYTES_STORAGE_SLOT - NUM_BYTES_ADDRESS..NUM_BYTES_STORAGE_SLOT];
    let proxy_admin_address = Address::from_slice(addr_bytes);

    info!("Proxy admin contract deployed at address:\n\t{:#x}", proxy_admin_address);

    // Write deployed addresses to deployments file
    let proxy_key = format!("{}_{}", deployment_prefix, PROXY_CONTRACT_KEY);
    let proxy_admin_key = format!("{}_{}", deployment_prefix, PROXY_ADMIN_CONTRACT_KEY);
    write_deployment_address(deployments_path, &proxy_key, proxy_address)?;
    write_deployment_address(deployments_path, &proxy_admin_key, proxy_admin_address)
}

/// Deploys the `Permit2` contract
pub async fn deploy_permit2(
    client: LocalWalletHttpClient,
    deployments_path: &str,
) -> Result<(), ScriptError> {
    let bytecode = hex::decode(PERMIT2_BYTECODE).map_err(err_str!(ScriptError::ArtifactParsing))?;

    let permit2_address = deploy_from_bytecode(&client, bytecode).await?;

    info!("Permit2 contract deployed at address:\n\t{:#x}", permit2_address);
    write_deployment_address(deployments_path, PERMIT2_CONTRACT_KEY, permit2_address)
}

/// Get the deploy code for a proxy contract.
/// Concretely, this is the bytecode of the proxy contract
/// concatenated with the calldata for the constructor.
fn get_proxy_deploy_code(
    implementation_address: Address,
    owner_address: Address,
    initialization_calldata: Bytes,
) -> Result<Vec<u8>, ScriptError> {
    let bytecode = hex::decode(TRANSPARENT_UPGRADEABLE_PROXY_BYTECODE)
        .map_err(err_str!(ScriptError::ArtifactParsing))?;

    let constructor_calldata = TransparentUpgradeableProxy::constructorCall {
        _logic: implementation_address,
        initialOwner: owner_address,
        _data: initialization_calldata,
    }
    .abi_encode();

    let deploy_code = [&bytecode[..], &constructor_calldata[..]].concat();
    Ok(deploy_code)
}

/// Deploys a contract from its "deploy code" (bytecode + any constructor
/// calldata). Returns the deployed contract's address.
async fn deploy_from_bytecode(
    client: &LocalWalletHttpClient,
    deploy_code: Vec<u8>,
) -> Result<Address, ScriptError> {
    let provider = client.provider();
    let tx = TransactionRequest::default().with_deploy_code(deploy_code);
    let receipt = send_raw_tx(&provider, tx).await?;

    let address = receipt.contract_address.ok_or_else(|| {
        ScriptError::ContractDeployment("Deployed contract address not found".to_string())
    })?;

    Ok(address)
}

/// Deploys the ERC-20 contract & approves the Permit2 contract
/// to spend the maximum amount of tokens for the provided
/// addresses.
pub async fn deploy_erc20(
    args: &DeployErc20Args,
    rpc_url: &str,
    priv_key: &str,
    client: LocalWalletHttpClient,
    deployments_path: &str,
) -> Result<Address, ScriptError> {
    if !args.account_skeys.is_empty() && args.funding_amount.is_none() {
        return Err(ScriptError::InvalidArguments(
            "funding amount must be provided if account skeys are provided".to_string(),
        ));
    }

    let contract = if args.as_wrapper {
        StylusContract::DummyWeth(args.symbol.clone())
    } else {
        StylusContract::DummyErc20(args.symbol.clone())
    };

    let deploy_stylus_args = DeployStylusArgs { contract, no_verify: false };
    let erc20_address = build_and_deploy_stylus_contract(
        &deploy_stylus_args,
        rpc_url,
        priv_key,
        client.clone(),
        deployments_path,
    )
    .await?;

    set_erc20_params(erc20_address, client.clone(), args).await?;
    if args.as_wrapper {
        let funding_amt = U256::from(WRAPPER_FUNDING_AMOUNT);
        fund_wrapper_contract(erc20_address, funding_amt, client).await?;
    }

    if !args.account_skeys.is_empty() {
        let permit2_address = read_deployment_address(deployments_path, PERMIT2_CONTRACT_KEY)?;

        for recipient_skey in &args.account_skeys {
            fund_and_approve_erc20(args, rpc_url, erc20_address, recipient_skey, permit2_address)
                .await?;
        }
    }

    Ok(erc20_address)
}

/// Sets the symbol, name, and decimals parameters for the ERC20 contract
async fn set_erc20_params(
    erc20_address: Address,
    client: LocalWalletHttpClient,
    args: &DeployErc20Args,
) -> Result<(), ScriptError> {
    let erc20 = DummyErc20::new(erc20_address, client.provider());

    info!("Setting {} contract parameters", args.symbol);

    send_tx(erc20.setSymbol(args.symbol.clone())).await?;
    send_tx(erc20.setName(args.name.clone())).await?;
    send_tx(erc20.setDecimals(args.decimals)).await?;

    Ok(())
}

/// Funds the provided account with the given amount of ERC20 tokens,
/// and approves the Permit2 contract to spend the maximum amount of the ERC20
async fn fund_and_approve_erc20(
    args: &DeployErc20Args,
    rpc_url: &str,
    erc20_address: Address,
    recipient_skey: &str,
    permit2_address: Address,
) -> Result<(), ScriptError> {
    let account_client = setup_client(recipient_skey, rpc_url).await?;
    let account_address = account_client.address();
    let erc20 = DummyErc20::new(erc20_address, account_client.provider());

    let funding_amount = args.funding_amount.unwrap();
    let symbol = args.symbol.clone();

    info!("Funding {:#x} with {} {} & approving Permit2", account_address, funding_amount, symbol);

    send_tx(erc20.mint(account_address, U256::from(funding_amount))).await?;
    send_tx(erc20.approve(permit2_address, U256::MAX)).await?;

    Ok(())
}

/// Fund a wrapper contract with ETH after it is deployed
async fn fund_wrapper_contract(
    wrapper_address: Address,
    value: U256,
    client: LocalWalletHttpClient,
) -> Result<(), ScriptError> {
    let weth_contract = DummyWeth::new(wrapper_address, client.provider());
    let call = weth_contract.deposit().value(value);
    send_tx(call).await.map(|_| ())
}

/// Builds and deploys a Stylus contract,
/// saving the deployment address to the deployments file
pub async fn build_and_deploy_stylus_contract(
    args: &DeployStylusArgs,
    rpc_url: &str,
    priv_key: &str,
    client: LocalWalletHttpClient,
    deployments_path: &str,
) -> Result<Address, ScriptError> {
    // Build the contract to WASM
    let wasm_file_path = build_stylus_contract(&args.contract, args.no_verify)?;

    // Deploy the contract
    let deployed_address =
        deploy_stylus_contract(wasm_file_path, rpc_url, priv_key, client, &args.contract).await?;

    // Write deployed address to deployments file
    write_stylus_contract_address(deployments_path, &args.contract, deployed_address)?;

    Ok(deployed_address)
}

/// Upgrades the darkpool implementation
pub async fn upgrade(
    args: &UpgradeArgs,
    client: LocalWalletHttpClient,
    deployments_path: &str,
) -> Result<(), ScriptError> {
    let proxy_admin_key = format!("{}_{}", StylusContract::Darkpool, PROXY_ADMIN_CONTRACT_KEY);
    let proxy_key = format!("{}_{}", StylusContract::Darkpool, PROXY_CONTRACT_KEY);

    let proxy_admin_address = read_deployment_address(deployments_path, &proxy_admin_key)?;
    let proxy_admin = ProxyAdmin::new(proxy_admin_address, client.provider());

    let proxy_address = read_deployment_address(deployments_path, &proxy_key)?;

    let implementation_contract =
        if args.test { StylusContract::DarkpoolTestContract } else { StylusContract::Darkpool };

    let implementation_address =
        read_stylus_deployment_address(deployments_path, &implementation_contract)?;

    let data = if let Some(calldata) = args.calldata.clone() {
        Bytes::from_hex(calldata).map_err(|e| ScriptError::CalldataConstruction(e.to_string()))?
    } else {
        Bytes::new()
    };

    send_tx(proxy_admin.upgradeAndCall(proxy_address, implementation_address, data))
        .await
        .map(|_| ())
}

/// Generates the hex-encoded calldata for the `setAllDelegateAddresses`
/// function on the darkpool contract
pub fn gen_set_all_delegate_addresses_calldata_hex(
    args: &SetAllDelegateAddressesCalldataArgs,
    deployments_path: &str,
) -> Result<(), ScriptError> {
    let core_wallet_ops_address =
        read_stylus_deployment_address(deployments_path, &StylusContract::CoreWalletOps)?;
    let core_match_settle_address =
        read_stylus_deployment_address(deployments_path, &StylusContract::CoreMatchSettle)?;
    let core_atomic_match_settle_address =
        read_stylus_deployment_address(deployments_path, &StylusContract::CoreAtomicMatchSettle)?;
    let verifier_core_address =
        read_stylus_deployment_address(deployments_path, &StylusContract::VerifierCore)?;
    let verifier_settlement_address =
        read_stylus_deployment_address(deployments_path, &StylusContract::VerifierSettlement)?;
    let transfer_executor_address =
        read_stylus_deployment_address(deployments_path, &StylusContract::TransferExecutor)?;

    // NOTE: We DELIBERATELY leave the core_malleable_match_settlement_address
    // unset, as it is not yet audited.
    let core_malleable_match_settle_address = Address::random();

    // Select the correct contracts for the test or production deployment
    let (vkeys_contract, merkle_contract) = if args.test {
        (StylusContract::TestVkeys, StylusContract::MerkleTestContract)
    } else {
        (StylusContract::Vkeys, StylusContract::Merkle)
    };

    let vkeys_address = read_stylus_deployment_address(deployments_path, &vkeys_contract)?;
    let merkle_address = read_stylus_deployment_address(deployments_path, &merkle_contract)?;

    let calldata = set_all_delegate_addresses_calldata(
        core_wallet_ops_address,
        core_match_settle_address,
        core_atomic_match_settle_address,
        core_malleable_match_settle_address,
        verifier_core_address,
        verifier_settlement_address,
        vkeys_address,
        merkle_address,
        transfer_executor_address,
    );

    let calldata_hex = hex::encode(calldata);

    println!("{}", calldata_hex);

    Ok(())
}

/// Computes verification keys for the protocol circuits
fn compute_vkeys<
    VWC: SingleProverCircuit,    // VALID WALLET CREATE
    VWU: SingleProverCircuit,    // VALID WALLET UPDATE
    VRFS: SingleProverCircuit,   // VALID RELAYER FEE SETTLEMENT
    VOFS: SingleProverCircuit,   // VALID OFFLINE FEE SETTLEMENT
    VFR: SingleProverCircuit,    // VALID FEE REDEMPTION
    VC: SingleProverCircuit,     // VALID COMMITMENTS
    VR: SingleProverCircuit,     // VALID REBLIND
    VMS: SingleProverCircuit,    // VALID MATCH SETTLE
    VMSWC: SingleProverCircuit,  // VALID MATCH SETTLE WITH COMMITMENTS
    VMSA: SingleProverCircuit,   // VALID MATCH SETTLE ATOMIC
    VMSAWC: SingleProverCircuit, // VALID MATCH SETTLE ATOMIC WITH COMMITMENTS
    VMMSA: SingleProverCircuit,  // VALID MALLEABLE MATCH SETTLE ATOMIC
>() -> Result<RenegadeVerificationKeys, ScriptError> {
    let valid_wallet_create = to_contract_vkey((*VWC::verifying_key()).clone())
        .map_err(|_| ScriptError::CircuitCreation)?;

    let valid_wallet_update = to_contract_vkey((*VWU::verifying_key()).clone())
        .map_err(|_| ScriptError::CircuitCreation)?;

    let valid_relayer_fee_settlement = to_contract_vkey((*VRFS::verifying_key()).clone())
        .map_err(|_| ScriptError::CircuitCreation)?;

    let valid_offline_fee_settlement = to_contract_vkey((*VOFS::verifying_key()).clone())
        .map_err(|_| ScriptError::CircuitCreation)?;

    let valid_fee_redemption = to_contract_vkey((*VFR::verifying_key()).clone())
        .map_err(|_| ScriptError::CircuitCreation)?;

    // Match settle vkeys
    let match_vkeys = gen_match_vkeys::<VC, VR, VMS>().map_err(|_| ScriptError::CircuitCreation)?;
    let valid_match_settle_with_commitments = to_contract_vkey((*VMSWC::verifying_key()).clone())
        .map_err(|_| ScriptError::CircuitCreation)?;
    let mut match_with_commitments_vkeys = match_vkeys.clone();
    match_with_commitments_vkeys.valid_match_settle_vkey = valid_match_settle_with_commitments;

    let match_linking_vkeys =
        gen_match_linking_vkeys::<VC>().map_err(|_| ScriptError::CircuitCreation)?;

    // Match settle atomic vkeys
    let match_atomic_vkeys =
        gen_match_atomic_vkeys::<VC, VR, VMSA>().map_err(|_| ScriptError::CircuitCreation)?;
    let valid_match_settle_atomic_with_commitments =
        to_contract_vkey((*VMSAWC::verifying_key()).clone())
            .map_err(|_| ScriptError::CircuitCreation)?;
    let mut match_atomic_with_commitments_vkeys = match_atomic_vkeys.clone();
    match_atomic_with_commitments_vkeys.settlement_vkey =
        valid_match_settle_atomic_with_commitments;

    let match_atomic_linking_vkeys =
        gen_match_atomic_linking_vkeys::<VC>().map_err(|_| ScriptError::CircuitCreation)?;

    // Malleable match settle atomic vkeys
    let malleable_match_atomic_vkeys = gen_malleable_match_atomic_vkeys::<VC, VR, VMMSA>()
        .map_err(|_| ScriptError::CircuitCreation)?;
    let malleable_match_atomic_linking_vkeys = gen_malleable_match_atomic_linking_vkeys::<VC>()
        .map_err(|_| ScriptError::CircuitCreation)?;

    Ok(RenegadeVerificationKeys {
        valid_wallet_create,
        valid_wallet_update,
        valid_relayer_fee_settlement,
        valid_offline_fee_settlement,
        valid_fee_redemption,
        match_vkeys,
        match_with_commitments_vkeys,
        match_linking_vkeys,
        match_atomic_vkeys,
        match_atomic_with_commitments_vkeys,
        match_atomic_linking_vkeys,
        malleable_match_atomic_vkeys,
        malleable_match_atomic_linking_vkeys,
    })
}

/// Write the protocol verification keys to the specified directory
fn write_vkeys(vkeys_dir: &str, vkeys: &RenegadeVerificationKeys) -> Result<(), ScriptError> {
    let valid_wallet_create = postcard::to_allocvec(&vkeys.valid_wallet_create)
        .map_err(|e| ScriptError::Serde(e.to_string()))?;

    let valid_wallet_update = postcard::to_allocvec(&vkeys.valid_wallet_update)
        .map_err(|e| ScriptError::Serde(e.to_string()))?;

    let valid_relayer_fee_settlement = postcard::to_allocvec(&vkeys.valid_relayer_fee_settlement)
        .map_err(|e| ScriptError::Serde(e.to_string()))?;

    let valid_offline_fee_settlement = postcard::to_allocvec(&vkeys.valid_offline_fee_settlement)
        .map_err(|e| ScriptError::Serde(e.to_string()))?;

    let valid_fee_redemption = postcard::to_allocvec(&vkeys.valid_fee_redemption)
        .map_err(|e| ScriptError::Serde(e.to_string()))?;

    let match_vkeys =
        postcard::to_allocvec(&vkeys.match_vkeys).map_err(|e| ScriptError::Serde(e.to_string()))?;
    let match_with_commitments_vkeys = postcard::to_allocvec(&vkeys.match_with_commitments_vkeys)
        .map_err(|e| ScriptError::Serde(e.to_string()))?;
    let match_linking_vkeys = postcard::to_allocvec(&vkeys.match_linking_vkeys)
        .map_err(|e| ScriptError::Serde(e.to_string()))?;

    let match_atomic_vkeys = postcard::to_allocvec(&vkeys.match_atomic_vkeys)
        .map_err(|e| ScriptError::Serde(e.to_string()))?;
    let match_atomic_with_commitments_vkeys =
        postcard::to_allocvec(&vkeys.match_atomic_with_commitments_vkeys)
            .map_err(|e| ScriptError::Serde(e.to_string()))?;
    let match_atomic_linking_vkeys = postcard::to_allocvec(&vkeys.match_atomic_linking_vkeys)
        .map_err(|e| ScriptError::Serde(e.to_string()))?;

    let malleable_match_atomic_vkeys = postcard::to_allocvec(&vkeys.malleable_match_atomic_vkeys)
        .map_err(|e| ScriptError::Serde(e.to_string()))?;
    let malleable_match_atomic_linking_vkeys =
        postcard::to_allocvec(&vkeys.malleable_match_atomic_linking_vkeys)
            .map_err(|e| ScriptError::Serde(e.to_string()))?;

    // The match vkeys & linking vkeys are serialized together
    let process_match_settle = [match_vkeys, match_linking_vkeys.clone()].concat();
    let process_match_settle_with_commitments =
        [match_with_commitments_vkeys, match_linking_vkeys].concat();

    // The match atomic vkeys & linking vkeys are serialized together
    let process_atomic_match_settle =
        [match_atomic_vkeys, match_atomic_linking_vkeys.clone()].concat();
    let process_atomic_match_settle_with_commitments =
        [match_atomic_with_commitments_vkeys, match_atomic_linking_vkeys].concat();

    // The malleable match atomic vkeys & linking vkeys are serialized together
    let process_malleable_match_atomic_settle =
        [malleable_match_atomic_vkeys, malleable_match_atomic_linking_vkeys].concat();

    for (file, data) in [
        (VALID_WALLET_CREATE_VKEY_FILE, valid_wallet_create),
        (VALID_WALLET_UPDATE_VKEY_FILE, valid_wallet_update),
        (VALID_RELAYER_FEE_SETTLEMENT_VKEY_FILE, valid_relayer_fee_settlement),
        (VALID_OFFLINE_FEE_SETTLEMENT_VKEY_FILE, valid_offline_fee_settlement),
        (VALID_FEE_REDEMPTION_VKEY_FILE, valid_fee_redemption),
        (PROCESS_MATCH_SETTLE_VKEYS_FILE, process_match_settle),
        (PROCESS_MATCH_SETTLE_WITH_COMMITMENTS_VKEYS_FILE, process_match_settle_with_commitments),
        (PROCESS_MATCH_SETTLE_ATOMIC_VKEYS_FILE, process_atomic_match_settle),
        (
            PROCESS_MATCH_SETTLE_ATOMIC_WITH_COMMITMENTS_VKEYS_FILE,
            process_atomic_match_settle_with_commitments,
        ),
        (PROCESS_MALLEABLE_MATCH_SETTLE_ATOMIC_VKEYS_FILE, process_malleable_match_atomic_settle),
    ] {
        write_vkey_file(vkeys_dir, file, &data)?;
    }

    Ok(())
}

/// Generates and writes either the testing or production protocol verification
/// keys to the specified directory
pub fn gen_vkeys(args: &GenVkeysArgs) -> Result<(), ScriptError> {
    let vkeys = if args.test {
        compute_vkeys::<
            DummyValidWalletCreate,
            DummyValidWalletUpdate,
            DummyValidRelayerFeeSettlement,
            DummyValidOfflineFeeSettlement,
            DummyValidFeeRedemption,
            DummyValidCommitments,
            DummyValidReblind,
            DummyValidMatchSettle,
            DummyValidMatchSettleWithCommitments,
            DummyValidMatchSettleAtomic,
            DummyValidMatchSettleAtomicWithCommitments,
            DummyValidMalleableMatchSettleAtomic,
        >()
    } else {
        compute_vkeys::<
            SizedValidWalletCreate,
            SizedValidWalletUpdate,
            SizedValidRelayerFeeSettlement,
            SizedValidOfflineFeeSettlement,
            SizedValidFeeRedemption,
            SizedValidCommitments,
            SizedValidReblind,
            SizedValidMatchSettle,
            SizedValidMatchSettleWithCommitments,
            SizedValidMatchSettleAtomic,
            SizedValidMatchSettleAtomicWithCommitments,
            SizedValidMalleableMatchSettleAtomic,
        >()
    }?;

    write_vkeys(&args.vkeys_dir, &vkeys)
}
