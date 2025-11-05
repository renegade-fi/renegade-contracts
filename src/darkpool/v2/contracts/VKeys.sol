// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { VerificationKey } from "renegade-lib/verifier/Types.sol";
import { VerificationKeys } from "darkpoolv2-lib/VerificationKeys.sol";
import { IVkeys } from "darkpoolv2-interfaces/IVkeys.sol";

/// @title VKeys
/// @author Renegade Eng
/// @notice Implementation of the verification keys in the darkpool v2
contract VKeys is IVkeys {
    // Individual verification keys
    /// @notice Get the verification key for `VALID BALANCE CREATE`
    /// @return The verification key for `VALID BALANCE CREATE`
    function balanceCreateKeys() external pure override returns (VerificationKey memory) {
        return __deserializeKey(VerificationKeys.VALID_BALANCE_CREATE_VKEY);
    }

    /// @notice Get the verification key for `VALID DEPOSIT`
    /// @return The verification key for `VALID DEPOSIT`
    function depositKeys() external pure override returns (VerificationKey memory) {
        return __deserializeKey(VerificationKeys.VALID_DEPOSIT_VKEY);
    }

    /// @notice Get the verification key for `VALID WITHDRAWAL`
    /// @return The verification key for `VALID WITHDRAWAL`
    function withdrawalKeys() external pure override returns (VerificationKey memory) {
        return __deserializeKey(VerificationKeys.VALID_WITHDRAWAL_VKEY);
    }

    /// @notice Get the verification key for `VALID NOTE REDEMPTION`
    /// @return The verification key for `VALID NOTE REDEMPTION`
    function noteRedemptionKeys() external pure override returns (VerificationKey memory) {
        return __deserializeKey(VerificationKeys.VALID_NOTE_REDEMPTION_VKEY);
    }

    /// @notice Get the verification key for `VALID PRIVATE PROTOCOL FEE PAYMENT`
    /// @return The verification key for `VALID PRIVATE PROTOCOL FEE PAYMENT`
    function privateProtocolFeePaymentKeys() external pure override returns (VerificationKey memory) {
        return __deserializeKey(VerificationKeys.VALID_PRIVATE_PROTOCOL_FEE_PAYMENT_VKEY);
    }

    /// @notice Get the verification key for `VALID PRIVATE RELAYER FEE PAYMENT`
    /// @return The verification key for `VALID PRIVATE RELAYER FEE PAYMENT`
    function privateRelayerFeePaymentKeys() external pure override returns (VerificationKey memory) {
        return __deserializeKey(VerificationKeys.VALID_PRIVATE_RELAYER_FEE_PAYMENT_VKEY);
    }

    /// @notice Get the verification key for `VALID PUBLIC PROTOCOL FEE PAYMENT`
    /// @return The verification key for `VALID PUBLIC PROTOCOL FEE PAYMENT`
    function publicProtocolFeePaymentKeys() external pure override returns (VerificationKey memory) {
        return __deserializeKey(VerificationKeys.VALID_PUBLIC_PROTOCOL_FEE_PAYMENT_VKEY);
    }

    /// @notice Get the verification key for `VALID PUBLIC RELAYER FEE PAYMENT`
    /// @return The verification key for `VALID PUBLIC RELAYER FEE PAYMENT`
    function publicRelayerFeePaymentKeys() external pure override returns (VerificationKey memory) {
        return __deserializeKey(VerificationKeys.VALID_PUBLIC_RELAYER_FEE_PAYMENT_VKEY);
    }

    /// @notice Deserialize a verification key
    /// @param vkeyBytes The bytes of the verification key
    /// @return vk The verification key
    function __deserializeKey(bytes memory vkeyBytes) internal pure returns (VerificationKey memory vk) {
        return abi.decode(vkeyBytes, (VerificationKey));
    }
}
