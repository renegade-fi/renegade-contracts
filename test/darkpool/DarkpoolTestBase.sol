// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { BN254 } from "solidity-bn254/BN254.sol";
import { ERC20Mock } from "oz-contracts/mocks/token/ERC20Mock.sol";
import { WethMock } from "../test-contracts/WethMock.sol";
import { IPermit2 } from "permit2/interfaces/IPermit2.sol";
import { DeployPermit2 } from "permit2-test/utils/DeployPermit2.sol";
import { Test } from "forge-std/Test.sol";
import { TestUtils } from "../utils/TestUtils.sol";
import { CalldataUtils } from "../utils/CalldataUtils.sol";
import { HuffDeployer } from "foundry-huff/HuffDeployer.sol";
import { Vm } from "forge-std/Vm.sol";
import { PublicRootKey } from "renegade-lib/darkpool/types/Keychain.sol";
import { EncryptionKey } from "renegade-lib/darkpool/types/Ciphertext.sol";
import { TestVerifier } from "../test-contracts/TestVerifier.sol";
import { Darkpool } from "renegade/Darkpool.sol";
import { NullifierLib } from "renegade-lib/darkpool/NullifierSet.sol";
import { WalletOperations } from "renegade-lib/darkpool/WalletOperations.sol";
import { IHasher } from "renegade-lib/interfaces/IHasher.sol";
import { IVerifier } from "renegade-lib/interfaces/IVerifier.sol";
import { PlonkProof } from "renegade-lib/verifier/Types.sol";

contract DarkpoolTestBase is CalldataUtils {
    using NullifierLib for NullifierLib.NullifierSet;

    Darkpool public darkpool;
    IHasher public hasher;
    NullifierLib.NullifierSet private testNullifierSet;
    IPermit2 public permit2;
    ERC20Mock public quoteToken;
    ERC20Mock public baseToken;
    WethMock public weth;

    address public protocolFeeAddr;

    bytes constant INVALID_NULLIFIER_REVERT_STRING = "Nullifier already spent";
    bytes constant INVALID_ROOT_REVERT_STRING = "Merkle root not in history";
    bytes constant INVALID_NOTE_ROOT_REVERT_STRING = "Note not in Merkle history";
    bytes constant INVALID_SIGNATURE_REVERT_STRING = "Invalid signature";
    bytes constant INVALID_PROTOCOL_FEE_REVERT_STRING = "Invalid protocol fee rate";
    bytes constant INVALID_PROTOCOL_FEE_KEY_REVERT_STRING = "Invalid protocol fee encryption key";
    bytes constant INVALID_ETH_VALUE_REVERT_STRING = "Invalid ETH value, should be zero unless selling native token";
    bytes constant INVALID_ETH_DEPOSIT_AMOUNT_REVERT_STRING = "msg.value does not match deposit amount";

    function setUp() public virtual {
        // Deploy a Permit2 instance for testing
        DeployPermit2 permit2Deployer = new DeployPermit2();
        permit2 = IPermit2(permit2Deployer.deployPermit2());

        // Deploy mock tokens for testing
        quoteToken = new ERC20Mock();
        baseToken = new ERC20Mock();
        weth = new WethMock();

        // Capitalize the weth contract
        vm.deal(address(weth), 100_000_000_000_000 ether);

        // Deploy the darkpool implementation contracts
        hasher = IHasher(HuffDeployer.deploy("libraries/poseidon2/poseidonHasher"));
        IVerifier verifier = new TestVerifier();
        protocolFeeAddr = vm.randomAddress();
        EncryptionKey memory protocolFeeKey = randomEncryptionKey();
        darkpool = new Darkpool(TEST_PROTOCOL_FEE, protocolFeeAddr, protocolFeeKey, weth, hasher, verifier, permit2);
    }

    /// @dev Get the base and quote token amounts for an address
    function baseQuoteBalances(address addr) public view returns (uint256 baseAmt, uint256 quoteAmt) {
        baseAmt = baseToken.balanceOf(addr);
        quoteAmt = quoteToken.balanceOf(addr);
    }

    /// @dev Get the weth and quote token balances for an address
    function wethQuoteBalances(address addr) public view returns (uint256 wethAmt, uint256 quoteAmt) {
        wethAmt = weth.balanceOf(addr);
        quoteAmt = quoteToken.balanceOf(addr);
    }

    /// @dev Get the ether and quote token balances for an address
    function etherQuoteBalances(address addr) public view returns (uint256 etherAmt, uint256 quoteAmt) {
        etherAmt = addr.balance;
        quoteAmt = quoteToken.balanceOf(addr);
    }

    // ---------------------------
    // | Library Primitive Tests |
    // ---------------------------

    /// @notice Test the nullifier set
    function test_nullifierSet() public {
        BN254.ScalarField nullifier = BN254.ScalarField.wrap(randomFelt());
        testNullifierSet.spend(nullifier); // Should succeed

        // Check that the nullifier is spent
        assertEq(testNullifierSet.isSpent(nullifier), true);

        // Should fail
        vm.expectRevert("Nullifier already spent");
        testNullifierSet.spend(nullifier);
    }
}
