//! Implementations of the various deploy scripts

use alloy_primitives::U256;
use circuit_types::traits::SingleProverCircuit;
use circuits::zk_circuits::{
    valid_commitments::SizedValidCommitments, valid_fee_redemption::SizedValidFeeRedemption,
    valid_match_settle::SizedValidMatchSettle,
    valid_offline_fee_settlement::SizedValidOfflineFeeSettlement, valid_reblind::SizedValidReblind,
    valid_relayer_fee_settlement::SizedValidRelayerFeeSettlement,
    valid_wallet_create::SizedValidWalletCreate, valid_wallet_update::SizedValidWalletUpdate,
};
use contracts_utils::{
    conversion::to_contract_vkey,
    proof_system::{
        dummy_renegade_circuits::{
            DummyValidCommitments, DummyValidFeeRedemption, DummyValidMatchSettle,
            DummyValidOfflineFeeSettlement, DummyValidReblind, DummyValidRelayerFeeSettlement,
            DummyValidWalletCreate, DummyValidWalletUpdate,
        },
        gen_match_linking_vkeys, gen_match_vkeys,
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
use std::{env, str::FromStr, sync::Arc};
use tracing::log::info;

use crate::{
    cli::{
        DeployErc20sArgs, DeployProxyArgs, DeployStylusArgs, DeployTestContractsArgs, GenVkeysArgs,
        UpgradeArgs,
    },
    constants::{
        DARKPOOL_PROXY_ADMIN_CONTRACT_KEY, DARKPOOL_PROXY_CONTRACT_KEY, DUMMY_ERC20_SYMBOL_ENV_VAR,
        NUM_BYTES_ADDRESS, NUM_BYTES_STORAGE_SLOT, NUM_DEPLOY_CONFIRMATIONS, PERMIT2_ABI,
        PERMIT2_BYTECODE, PERMIT2_CONTRACT_KEY, PROCESS_MATCH_SETTLE_VKEYS_FILE, PROXY_ABI,
        PROXY_ADMIN_STORAGE_SLOT, PROXY_BYTECODE, TEST_ERC20_TICKER, TEST_FUNDING_AMOUNT,
        VALID_FEE_REDEMPTION_VKEY_FILE, VALID_OFFLINE_FEE_SETTLEMENT_VKEY_FILE,
        VALID_RELAYER_FEE_SETTLEMENT_VKEY_FILE, VALID_WALLET_CREATE_VKEY_FILE,
        VALID_WALLET_UPDATE_VKEY_FILE,
    },
    errors::ScriptError,
    solidity::{DummyErc20Contract, ProxyAdminContract},
    types::{RenegadeVerificationKeys, StylusContract},
    utils::{
        build_stylus_contract, darkpool_initialize_calldata, deploy_stylus_contract,
        get_contract_key, get_public_encryption_key, parse_addr_from_deployments_file,
        setup_client, write_deployed_address, write_vkey_file, LocalWalletHttpClient,
    },
};

/// Builds & deploys all of the contracts necessary for running the integration testing suite.
///
/// This includes generating fresh verification keys for testing.
pub async fn deploy_test_contracts(
    args: DeployTestContractsArgs,
    rpc_url: &str,
    priv_key: &str,
    client: Arc<LocalWalletHttpClient>,
    deployments_path: &str,
) -> Result<(), ScriptError> {
    info!("Generating testing verification keys");
    let gen_vkeys_args = GenVkeysArgs {
        vkeys_dir: args.vkeys_dir.clone(),
        test: true,
    };
    gen_vkeys(gen_vkeys_args)?;

    let mut deploy_stylus_args = DeployStylusArgs {
        contract: StylusContract::TestVkeys,
        no_verify: args.no_verify,
    };

    info!("Deploying testing verification keys");
    build_and_deploy_stylus_contract(
        deploy_stylus_args,
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
        deploy_stylus_args,
        rpc_url,
        priv_key,
        client.clone(),
        deployments_path,
    )
    .await?;

    info!("Deploying precompiles testing contract");
    deploy_stylus_args.contract = StylusContract::PrecompileTestContract;
    build_and_deploy_stylus_contract(
        deploy_stylus_args,
        rpc_url,
        priv_key,
        client.clone(),
        deployments_path,
    )
    .await?;

    info!("Deploying Merkle testing contract");
    deploy_stylus_args.contract = StylusContract::MerkleTestContract;
    build_and_deploy_stylus_contract(
        deploy_stylus_args,
        rpc_url,
        priv_key,
        client.clone(),
        deployments_path,
    )
    .await?;

    info!("Deploying transfer executor contract");
    deploy_stylus_args.contract = StylusContract::TransferExecutor;
    build_and_deploy_stylus_contract(
        deploy_stylus_args,
        rpc_url,
        priv_key,
        client.clone(),
        deployments_path,
    )
    .await?;

    info!("Deploying Permit2 contract");
    deploy_permit2(client.clone(), deployments_path).await?;

    info!("Deploying test ERC-20 contract");
    let deploy_erc20_args = DeployErc20sArgs {
        tickers: vec![TEST_ERC20_TICKER.to_string()],
        funding_amount: TEST_FUNDING_AMOUNT,
        account_skeys: vec![priv_key.to_string()],
    };
    deploy_erc20s(
        deploy_erc20_args,
        rpc_url,
        priv_key,
        client.clone(),
        deployments_path,
    )
    .await?;

    info!("Deploying verifier contract");
    deploy_stylus_args.contract = StylusContract::Verifier;
    build_and_deploy_stylus_contract(
        deploy_stylus_args,
        rpc_url,
        priv_key,
        client.clone(),
        deployments_path,
    )
    .await?;

    info!("Deploying darkpool core contract");
    deploy_stylus_args.contract = StylusContract::DarkpoolCore;
    build_and_deploy_stylus_contract(
        deploy_stylus_args,
        rpc_url,
        priv_key,
        client.clone(),
        deployments_path,
    )
    .await?;

    info!("Deploying darkpool testing contract");
    deploy_stylus_args.contract = StylusContract::DarkpoolTestContract;
    build_and_deploy_stylus_contract(
        deploy_stylus_args,
        rpc_url,
        priv_key,
        client.clone(),
        deployments_path,
    )
    .await?;

    info!("Deploying proxy contract");
    let deploy_proxy_args = DeployProxyArgs {
        owner: args.owner,
        fee: thread_rng().gen(),
        protocol_public_encryption_key: None,
    };
    deploy_proxy(deploy_proxy_args, client, deployments_path).await?;

    Ok(())
}

/// Deploys the `TransparentUpgradeableProxy` and `ProxyAdmin` contracts
pub async fn deploy_proxy(
    args: DeployProxyArgs,
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

    let darkpool_address = parse_addr_from_deployments_file(
        deployments_path,
        get_contract_key(StylusContract::Darkpool),
    )?;
    let darkpool_core_address = parse_addr_from_deployments_file(
        deployments_path,
        get_contract_key(StylusContract::DarkpoolCore),
    )?;
    let merkle_address = parse_addr_from_deployments_file(
        deployments_path,
        get_contract_key(StylusContract::Merkle),
    )?;
    let verifier_address = parse_addr_from_deployments_file(
        deployments_path,
        get_contract_key(StylusContract::Verifier),
    )?;

    let vkeys_address = parse_addr_from_deployments_file(
        deployments_path,
        get_contract_key(StylusContract::Vkeys),
    )?;

    let transfer_executor_address = parse_addr_from_deployments_file(
        deployments_path,
        get_contract_key(StylusContract::TransferExecutor),
    )?;

    let permit2_address = parse_addr_from_deployments_file(deployments_path, PERMIT2_CONTRACT_KEY)?;

    let owner_address = Address::from_str(&args.owner)
        .map_err(|e| ScriptError::CalldataConstruction(e.to_string()))?;

    let protocol_fee = U256::from(args.fee);

    let protocol_public_encryption_key =
        get_public_encryption_key(args.protocol_public_encryption_key)?;

    let darkpool_calldata = Bytes::from(darkpool_initialize_calldata(
        darkpool_core_address,
        verifier_address,
        vkeys_address,
        merkle_address,
        transfer_executor_address,
        permit2_address,
        protocol_fee,
        protocol_public_encryption_key,
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

    info!(
        "Proxy contract deployed at address:\n\t{:#x}",
        proxy_address
    );

    // Get proxy admin contract address
    // This is the recommended way to get the proxy admin address:
    // https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.0.0/contracts/proxy/ERC1967/ERC1967Utils.sol#L104-L106
    let proxy_admin_address = Address::from_slice(
        &client
            .get_storage_at(
                proxy_address,
                // Can `unwrap` here since we know the storage slot constitutes a valid H256
                H256::from_str(PROXY_ADMIN_STORAGE_SLOT).unwrap(),
                None, /* block */
            )
            .await
            .map_err(|e| ScriptError::ContractInteraction(e.to_string()))?
            [NUM_BYTES_STORAGE_SLOT - NUM_BYTES_ADDRESS..NUM_BYTES_STORAGE_SLOT],
    );

    info!(
        "Proxy admin contract deployed at address:\n\t{:#x}",
        proxy_admin_address
    );

    // Write deployed addresses to deployments file
    write_deployed_address(deployments_path, DARKPOOL_PROXY_CONTRACT_KEY, proxy_address)?;
    write_deployed_address(
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

    info!(
        "Permit2 contract deployed at address:\n\t{:#x}",
        permit2_address
    );

    write_deployed_address(deployments_path, PERMIT2_CONTRACT_KEY, permit2_address)
}

/// Deploys the ERC-20 contracts & approves the darkpool
/// to spend the maximum amount of tokens for the provided
/// addresses.
///
/// Note: the provided tickers will not actually be used as the contract's
/// name or symbol, but rather as a way to identify the contract in the deployments file.
pub async fn deploy_erc20s(
    args: DeployErc20sArgs,
    rpc_url: &str,
    priv_key: &str,
    client: Arc<LocalWalletHttpClient>,
    deployments_path: &str,
) -> Result<(), ScriptError> {
    let mut erc20_addresses = Vec::with_capacity(args.tickers.len());
    for ticker in args.tickers {
        env::set_var(DUMMY_ERC20_SYMBOL_ENV_VAR, &ticker);

        let wasm_file_path =
            build_stylus_contract(StylusContract::DummyErc20, false /* no_verify */)?;

        erc20_addresses.push(
            deploy_stylus_contract(
                wasm_file_path.clone(),
                rpc_url,
                priv_key,
                client.clone(),
                StylusContract::DummyErc20,
                deployments_path,
                Some(&ticker),
            )
            .await?,
        );
    }

    let permit2_address = parse_addr_from_deployments_file(deployments_path, PERMIT2_CONTRACT_KEY)?;

    for erc20_address in erc20_addresses {
        for skey in &args.account_skeys {
            let account_client = setup_client(skey, rpc_url).await?;
            let account_address = account_client.default_sender().unwrap();
            let erc20 = DummyErc20Contract::new(erc20_address, account_client);

            mint_erc20(&erc20, account_address, args.funding_amount).await?;
            approve_erc20_max(&erc20, permit2_address).await?;
        }
    }

    Ok(())
}

/// Mints ERC20 tokens for the provided address
async fn mint_erc20(
    erc20: &DummyErc20Contract<impl Middleware + 'static>,
    recipient_address: Address,
    amount: u128,
) -> Result<(), ScriptError> {
    erc20
        .mint(recipient_address, EthersU256::from(amount))
        .send()
        .await
        .map_err(|e| ScriptError::ContractInteraction(e.to_string()))?
        .await
        .map_err(|e| ScriptError::ContractInteraction(e.to_string()))
        .map(|_| ())
}

/// Approves the darkpool to spend the maximum amount of the given ERC20
async fn approve_erc20_max(
    erc20: &DummyErc20Contract<impl Middleware + 'static>,
    spender_address: Address,
) -> Result<(), ScriptError> {
    erc20
        .approve(spender_address, EthersU256::MAX)
        .send()
        .await
        .map_err(|e| ScriptError::ContractInteraction(e.to_string()))?
        .await
        .map_err(|e| ScriptError::ContractInteraction(e.to_string()))
        .map(|_| ())
}

/// Builds and deploys a Stylus contract
pub async fn build_and_deploy_stylus_contract(
    args: DeployStylusArgs,
    rpc_url: &str,
    priv_key: &str,
    client: Arc<LocalWalletHttpClient>,
    deployments_path: &str,
) -> Result<(), ScriptError> {
    let wasm_file_path = build_stylus_contract(args.contract, args.no_verify)?;
    deploy_stylus_contract(
        wasm_file_path,
        rpc_url,
        priv_key,
        client,
        args.contract,
        deployments_path,
        None,
    )
    .await
    .map(|_| ())
}

/// Upgrades the darkpool implementation
pub async fn upgrade(
    args: UpgradeArgs,
    client: Arc<LocalWalletHttpClient>,
    deployments_path: &str,
) -> Result<(), ScriptError> {
    let proxy_admin_address =
        parse_addr_from_deployments_file(deployments_path, DARKPOOL_PROXY_ADMIN_CONTRACT_KEY)?;
    let proxy_admin = ProxyAdminContract::new(proxy_admin_address, client);

    let proxy_address =
        parse_addr_from_deployments_file(deployments_path, DARKPOOL_PROXY_CONTRACT_KEY)?;

    let implementation_address = parse_addr_from_deployments_file(
        deployments_path,
        get_contract_key(StylusContract::Darkpool),
    )?;

    let data = if let Some(calldata) = args.calldata {
        Bytes::from_hex(calldata).map_err(|e| ScriptError::CalldataConstruction(e.to_string()))?
    } else {
        Bytes::new()
    };

    proxy_admin
        .upgrade_and_call(proxy_address, implementation_address, data)
        .send()
        .await
        .map_err(|e| ScriptError::ContractInteraction(e.to_string()))?
        .await
        .map_err(|e| ScriptError::ContractInteraction(e.to_string()))?;

    Ok(())
}

/// Computes verification keys for the protocol circuits
fn compute_vkeys<
    VWC: SingleProverCircuit,  /* VALID WALLET CREATE */
    VWU: SingleProverCircuit,  /* VALID WALLET UPDATE */
    VRFS: SingleProverCircuit, /* VALID RELAYER FEE SETTLEMENT */
    VOFS: SingleProverCircuit, /* VALID OFFLINE FEE SETTLEMENT */
    VFR: SingleProverCircuit,  /* VALID FEE REDEMPTION */
    VC: SingleProverCircuit,   /* VALID COMMITMENTS */
    VR: SingleProverCircuit,   /* VALID REBLIND */
    VMS: SingleProverCircuit,  /* VALID MATCH SETTLE */
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

    Ok(RenegadeVerificationKeys {
        valid_wallet_create,
        valid_wallet_update,
        valid_relayer_fee_settlement,
        valid_offline_fee_settlement,
        valid_fee_redemption,
        match_vkeys,
        match_linking_vkeys,
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

    // The match vkeys & linking vkeys are serialized together
    let process_match_settle = [match_vkeys, match_linking_vkeys].concat();

    for (file, data) in [
        (VALID_WALLET_CREATE_VKEY_FILE, valid_wallet_create),
        (VALID_WALLET_UPDATE_VKEY_FILE, valid_wallet_update),
        (
            VALID_RELAYER_FEE_SETTLEMENT_VKEY_FILE,
            valid_relayer_fee_settlement,
        ),
        (
            VALID_OFFLINE_FEE_SETTLEMENT_VKEY_FILE,
            valid_offline_fee_settlement,
        ),
        (VALID_FEE_REDEMPTION_VKEY_FILE, valid_fee_redemption),
        (PROCESS_MATCH_SETTLE_VKEYS_FILE, process_match_settle),
    ] {
        write_vkey_file(vkeys_dir, file, &data)?;
    }

    Ok(())
}

/// Generates and writes either the testing or production protocol verification keys
/// to the specified directory
pub fn gen_vkeys(args: GenVkeysArgs) -> Result<(), ScriptError> {
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
        >()
    }?;

    write_vkeys(&args.vkeys_dir, &vkeys)
}
