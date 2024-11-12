//! Implementations of the various deploy scripts

use alloy_primitives::U256;
use circuit_types::traits::SingleProverCircuit;
use circuits::zk_circuits::{
    valid_commitments::SizedValidCommitments, valid_fee_redemption::SizedValidFeeRedemption,
    valid_match_settle::SizedValidMatchSettle,
    valid_match_settle_atomic::SizedValidMatchSettleAtomic,
    valid_offline_fee_settlement::SizedValidOfflineFeeSettlement, valid_reblind::SizedValidReblind,
    valid_relayer_fee_settlement::SizedValidRelayerFeeSettlement,
    valid_wallet_create::SizedValidWalletCreate, valid_wallet_update::SizedValidWalletUpdate,
};
use contracts_utils::{
    conversion::to_contract_vkey,
    proof_system::{
        dummy_renegade_circuits::{
            DummyValidCommitments, DummyValidFeeRedemption, DummyValidMatchSettle,
            DummyValidMatchSettleAtomic, DummyValidOfflineFeeSettlement, DummyValidReblind,
            DummyValidRelayerFeeSettlement, DummyValidWalletCreate, DummyValidWalletUpdate,
        },
        gen_match_atomic_linking_vkeys, gen_match_atomic_vkeys, gen_match_linking_vkeys,
        gen_match_vkeys,
    },
};
use ethers::{
    abi::{Address, Contract},
    middleware::contract::ContractFactory,
    providers::Middleware,
    types::{Bytes, H256, U256 as EthersU256},
    utils::hex::FromHex,
};
use rand::{thread_rng, Rng};
use std::{str::FromStr, sync::Arc};
use tracing::log::info;

use crate::{
    cli::{
        DeployErc20Args, DeployProxyArgs, DeployStylusArgs, DeployTestContractsArgs, GenVkeysArgs,
        UpgradeArgs,
    },
    constants::{
        DARKPOOL_PROXY_ADMIN_CONTRACT_KEY, DARKPOOL_PROXY_CONTRACT_KEY, NUM_BYTES_ADDRESS,
        NUM_BYTES_STORAGE_SLOT, NUM_DEPLOY_CONFIRMATIONS, PERMIT2_ABI, PERMIT2_BYTECODE,
        PERMIT2_CONTRACT_KEY, PROCESS_MATCH_SETTLE_ATOMIC_VKEYS_FILE,
        PROCESS_MATCH_SETTLE_VKEYS_FILE, PROXY_ABI, PROXY_ADMIN_STORAGE_SLOT, PROXY_BYTECODE,
        TEST_ERC20_DECIMALS, TEST_ERC20_TICKER1, TEST_ERC20_TICKER2, TEST_FUNDING_AMOUNT,
        VALID_FEE_REDEMPTION_VKEY_FILE, VALID_OFFLINE_FEE_SETTLEMENT_VKEY_FILE,
        VALID_RELAYER_FEE_SETTLEMENT_VKEY_FILE, VALID_WALLET_CREATE_VKEY_FILE,
        VALID_WALLET_UPDATE_VKEY_FILE,
    },
    errors::ScriptError,
    solidity::{DummyErc20Contract, ProxyAdminContract},
    types::{RenegadeVerificationKeys, StylusContract},
    utils::{
        build_stylus_contract, darkpool_initialize_calldata, deploy_stylus_contract,
        get_protocol_external_fee_collection_address, get_public_encryption_key,
        read_deployment_address, read_stylus_deployment_address, send_contract_call, setup_client,
        write_deployment_address, write_stylus_contract_address, write_vkey_file,
        LocalWalletHttpClient,
    },
};

/// Builds & deploys all of the contracts necessary for running the integration
/// testing suite.
///
/// This includes generating fresh verification keys for testing.
pub async fn deploy_test_contracts(
    args: &DeployTestContractsArgs,
    rpc_url: &str,
    priv_key: &str,
    client: Arc<LocalWalletHttpClient>,
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
    deploy_erc20(&deploy_erc20_args, rpc_url, priv_key, client.clone(), deployments_path).await?;

    deploy_erc20_args.symbol = TEST_ERC20_TICKER2.to_string();
    deploy_erc20_args.name = TEST_ERC20_TICKER2.to_string();
    deploy_erc20_args.as_wrapper = false; // deploy the second erc20 as a normal erc20
    deploy_erc20(&deploy_erc20_args, rpc_url, priv_key, client.clone(), deployments_path).await?;

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

    info!("Deploying core settlement contract");
    deploy_stylus_args.contract = StylusContract::CoreSettlement;
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

    info!("Deploying proxy contract");
    let deploy_proxy_args = DeployProxyArgs {
        owner: args.owner.clone(),
        fee: thread_rng().gen(),
        protocol_public_encryption_key: None,
        protocol_external_fee_collection_address: None,
        test: true,
    };
    deploy_proxy(&deploy_proxy_args, client, deployments_path).await?;

    Ok(())
}

/// Deploys the `TransparentUpgradeableProxy` and `ProxyAdmin` contracts
pub async fn deploy_proxy(
    args: &DeployProxyArgs,
    client: Arc<LocalWalletHttpClient>,
    deployments_path: &str,
) -> Result<(), ScriptError> {
    // Get proxy contract ABI and bytecode
    let abi: Contract =
        serde_json::from_str(PROXY_ABI).map_err(|e| ScriptError::ArtifactParsing(e.to_string()))?;

    let bytecode =
        Bytes::from_hex(PROXY_BYTECODE).map_err(|e| ScriptError::ArtifactParsing(e.to_string()))?;

    let proxy_factory = ContractFactory::new(abi, bytecode, client.clone());

    // Parse proxy contract constructor arguments

    let darkpool_contract =
        if args.test { StylusContract::DarkpoolTestContract } else { StylusContract::Darkpool };
    let merkle_contract =
        if args.test { StylusContract::MerkleTestContract } else { StylusContract::Merkle };
    let vkeys_contract = if args.test { StylusContract::TestVkeys } else { StylusContract::Vkeys };

    let darkpool_address = read_stylus_deployment_address(deployments_path, &darkpool_contract)?;
    let core_wallet_ops_address =
        read_stylus_deployment_address(deployments_path, &StylusContract::CoreWalletOps)?;
    let core_settlement_address =
        read_stylus_deployment_address(deployments_path, &StylusContract::CoreSettlement)?;
    let merkle_address = read_stylus_deployment_address(deployments_path, &merkle_contract)?;
    let verifier_core_address =
        read_stylus_deployment_address(deployments_path, &StylusContract::VerifierCore)?;
    let verifier_settlement_address =
        read_stylus_deployment_address(deployments_path, &StylusContract::VerifierSettlement)?;

    let vkeys_address = read_stylus_deployment_address(deployments_path, &vkeys_contract)?;

    let transfer_executor_address =
        read_stylus_deployment_address(deployments_path, &StylusContract::TransferExecutor)?;

    let permit2_address = read_deployment_address(deployments_path, PERMIT2_CONTRACT_KEY)?;

    let owner_address = Address::from_str(&args.owner)
        .map_err(|e| ScriptError::CalldataConstruction(e.to_string()))?;

    let protocol_fee = U256::from(args.fee);

    let protocol_public_encryption_key =
        get_public_encryption_key(args.protocol_public_encryption_key.clone())?;

    let protocol_external_fee_collection_address = get_protocol_external_fee_collection_address(
        args.protocol_external_fee_collection_address.clone(),
    )?;

    let darkpool_calldata = Bytes::from(darkpool_initialize_calldata(
        core_wallet_ops_address,
        core_settlement_address,
        verifier_core_address,
        verifier_settlement_address,
        vkeys_address,
        merkle_address,
        transfer_executor_address,
        permit2_address,
        protocol_fee,
        protocol_public_encryption_key,
        protocol_external_fee_collection_address,
    )?);

    // Deploy proxy contract
    let proxy_contract = proxy_factory
        .deploy((darkpool_address, owner_address, darkpool_calldata))
        .map_err(|e| ScriptError::ContractDeployment(e.to_string()))?
        .confirmations(NUM_DEPLOY_CONFIRMATIONS)
        .send()
        .await
        .map_err(|e| ScriptError::ContractDeployment(e.to_string()))?;

    let proxy_address = proxy_contract.address();

    info!("Proxy contract deployed at address:\n\t{:#x}", proxy_address);

    // Get proxy admin contract address
    // This is the recommended way to get the proxy admin address:
    // https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.0.0/contracts/proxy/ERC1967/ERC1967Utils.sol#L104-L106
    let proxy_admin_address = Address::from_slice(
        &client
            .get_storage_at(
                proxy_address,
                // Can `unwrap` here since we know the storage slot constitutes a valid H256
                H256::from_str(PROXY_ADMIN_STORAGE_SLOT).unwrap(),
                None, // block
            )
            .await
            .map_err(|e| ScriptError::ContractInteraction(e.to_string()))?
            [NUM_BYTES_STORAGE_SLOT - NUM_BYTES_ADDRESS..NUM_BYTES_STORAGE_SLOT],
    );

    info!("Proxy admin contract deployed at address:\n\t{:#x}", proxy_admin_address);

    // Write deployed addresses to deployments file
    write_deployment_address(deployments_path, DARKPOOL_PROXY_CONTRACT_KEY, proxy_address)?;
    write_deployment_address(
        deployments_path,
        DARKPOOL_PROXY_ADMIN_CONTRACT_KEY,
        proxy_admin_address,
    )
}

/// Deploys the `Permit2` contract
pub async fn deploy_permit2(
    client: Arc<LocalWalletHttpClient>,
    deployments_path: &str,
) -> Result<(), ScriptError> {
    // Get Permit2 contract ABI and bytecode
    let abi: Contract = serde_json::from_str(PERMIT2_ABI)
        .map_err(|e| ScriptError::ArtifactParsing(e.to_string()))?;

    let bytecode = Bytes::from_hex(PERMIT2_BYTECODE)
        .map_err(|e| ScriptError::ArtifactParsing(e.to_string()))?;

    let permit2_factory = ContractFactory::new(abi, bytecode, client.clone());

    let permit2_contract = permit2_factory
        .deploy(())
        .map_err(|e| ScriptError::ContractDeployment(e.to_string()))?
        .confirmations(NUM_DEPLOY_CONFIRMATIONS)
        .send()
        .await
        .map_err(|e| ScriptError::ContractDeployment(e.to_string()))?;

    let permit2_address = permit2_contract.address();

    info!("Permit2 contract deployed at address:\n\t{:#x}", permit2_address);

    write_deployment_address(deployments_path, PERMIT2_CONTRACT_KEY, permit2_address)
}

/// Deploys the ERC-20 contract & approves the Permit2 contract
/// to spend the maximum amount of tokens for the provided
/// addresses.
pub async fn deploy_erc20(
    args: &DeployErc20Args,
    rpc_url: &str,
    priv_key: &str,
    client: Arc<LocalWalletHttpClient>,
    deployments_path: &str,
) -> Result<(), ScriptError> {
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

    set_erc20_params(erc20_address, client, args).await?;

    if !args.account_skeys.is_empty() {
        let permit2_address = read_deployment_address(deployments_path, PERMIT2_CONTRACT_KEY)?;

        for recipient_skey in &args.account_skeys {
            fund_and_approve_erc20(args, rpc_url, erc20_address, recipient_skey, permit2_address)
                .await?;
        }
    }

    Ok(())
}

/// Sets the symbol, name, and decimals parameters for the ERC20 contract
async fn set_erc20_params(
    erc20_address: Address,
    client: Arc<LocalWalletHttpClient>,
    args: &DeployErc20Args,
) -> Result<(), ScriptError> {
    let erc20 = DummyErc20Contract::new(erc20_address, client);

    info!("Setting {} contract parameters", args.symbol);

    send_contract_call(erc20.set_symbol(args.symbol.clone())).await?;
    send_contract_call(erc20.set_name(args.name.clone())).await?;
    send_contract_call(erc20.set_decimals(args.decimals)).await?;

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
    let account_address = account_client.default_sender().unwrap();
    let erc20 = DummyErc20Contract::new(erc20_address, account_client);

    let funding_amount = args.funding_amount.unwrap();
    let symbol = args.symbol.clone();

    info!("Funding {:#x} with {} {} & approving Permit2", account_address, funding_amount, symbol);

    send_contract_call(erc20.mint(account_address, EthersU256::from(funding_amount))).await?;
    send_contract_call(erc20.approve(permit2_address, EthersU256::MAX)).await?;

    Ok(())
}

/// Builds and deploys a Stylus contract,
/// saving the deployment address to the deployments file
pub async fn build_and_deploy_stylus_contract(
    args: &DeployStylusArgs,
    rpc_url: &str,
    priv_key: &str,
    client: Arc<LocalWalletHttpClient>,
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
    client: Arc<LocalWalletHttpClient>,
    deployments_path: &str,
) -> Result<(), ScriptError> {
    let proxy_admin_address =
        read_deployment_address(deployments_path, DARKPOOL_PROXY_ADMIN_CONTRACT_KEY)?;
    let proxy_admin = ProxyAdminContract::new(proxy_admin_address, client);

    let proxy_address = read_deployment_address(deployments_path, DARKPOOL_PROXY_CONTRACT_KEY)?;

    let implementation_address =
        read_stylus_deployment_address(deployments_path, &StylusContract::Darkpool)?;

    let data = if let Some(calldata) = args.calldata.clone() {
        Bytes::from_hex(calldata).map_err(|e| ScriptError::CalldataConstruction(e.to_string()))?
    } else {
        Bytes::new()
    };

    send_contract_call(proxy_admin.upgrade_and_call(proxy_address, implementation_address, data))
        .await?;

    Ok(())
}

/// Computes verification keys for the protocol circuits
fn compute_vkeys<
    VWC: SingleProverCircuit,  // VALID WALLET CREATE
    VWU: SingleProverCircuit,  // VALID WALLET UPDATE
    VRFS: SingleProverCircuit, // VALID RELAYER FEE SETTLEMENT
    VOFS: SingleProverCircuit, // VALID OFFLINE FEE SETTLEMENT
    VFR: SingleProverCircuit,  // VALID FEE REDEMPTION
    VC: SingleProverCircuit,   // VALID COMMITMENTS
    VR: SingleProverCircuit,   // VALID REBLIND
    VMS: SingleProverCircuit,  // VALID MATCH SETTLE
    VMSA: SingleProverCircuit, // VALID MATCH SETTLE ATOMIC
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

    let match_vkeys = gen_match_vkeys::<VC, VR, VMS>().map_err(|_| ScriptError::CircuitCreation)?;

    let match_linking_vkeys =
        gen_match_linking_vkeys::<VC>().map_err(|_| ScriptError::CircuitCreation)?;

    let match_atomic_vkeys =
        gen_match_atomic_vkeys::<VC, VR, VMSA>().map_err(|_| ScriptError::CircuitCreation)?;

    let match_atomic_linking_vkeys =
        gen_match_atomic_linking_vkeys::<VC>().map_err(|_| ScriptError::CircuitCreation)?;

    Ok(RenegadeVerificationKeys {
        valid_wallet_create,
        valid_wallet_update,
        valid_relayer_fee_settlement,
        valid_offline_fee_settlement,
        valid_fee_redemption,
        match_vkeys,
        match_linking_vkeys,
        match_atomic_vkeys,
        match_atomic_linking_vkeys,
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
    let match_linking_vkeys = postcard::to_allocvec(&vkeys.match_linking_vkeys)
        .map_err(|e| ScriptError::Serde(e.to_string()))?;

    let match_atomic_vkeys = postcard::to_allocvec(&vkeys.match_atomic_vkeys)
        .map_err(|e| ScriptError::Serde(e.to_string()))?;
    let match_atomic_linking_vkeys = postcard::to_allocvec(&vkeys.match_atomic_linking_vkeys)
        .map_err(|e| ScriptError::Serde(e.to_string()))?;

    // The match vkeys & linking vkeys are serialized together
    let process_match_settle = [match_vkeys, match_linking_vkeys].concat();

    // The match atomic vkeys & linking vkeys are serialized together
    let process_atomic_match_settle = [match_atomic_vkeys, match_atomic_linking_vkeys].concat();

    for (file, data) in [
        (VALID_WALLET_CREATE_VKEY_FILE, valid_wallet_create),
        (VALID_WALLET_UPDATE_VKEY_FILE, valid_wallet_update),
        (VALID_RELAYER_FEE_SETTLEMENT_VKEY_FILE, valid_relayer_fee_settlement),
        (VALID_OFFLINE_FEE_SETTLEMENT_VKEY_FILE, valid_offline_fee_settlement),
        (VALID_FEE_REDEMPTION_VKEY_FILE, valid_fee_redemption),
        (PROCESS_MATCH_SETTLE_VKEYS_FILE, process_match_settle),
        (PROCESS_MATCH_SETTLE_ATOMIC_VKEYS_FILE, process_atomic_match_settle),
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
            DummyValidMatchSettleAtomic,
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
            SizedValidMatchSettleAtomic,
        >()
    }?;

    write_vkeys(&args.vkeys_dir, &vkeys)
}
