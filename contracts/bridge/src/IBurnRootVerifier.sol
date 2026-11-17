// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

/// @title IBurnRootVerifier
/// @notice The one interface through which `BridgeVault` accepts LEZ burn roots (docs/ARCHITECTURE.md §3.6). The prototype
///         implementation is `EcdsaRootVerifier` (INTERIM, CUSTODIAL, NOT TRUSTLESS); later implementations
///         are new deployments behind it. Optional milestone O adds a committee-certified checkpoint verifier (q of N
///         LEZ sequencer committee keys, NOT TRUSTLESS). A verifier that checks Bedrock finality and LEZ execution
///         could be trustless; that is not part of this grant.
interface IBurnRootVerifier {
    /// Reverts unless `attestation` authorises `burnRoot` with `count` leaves for (token, denom) of the calling
    /// vault at LEZ block (lezHeight, lezBlockHash) (vault == msg.sender, block.chainid, CONFIG_ID bound inside).
    function verifyRoot(
        address token,
        uint256 denom,
        bytes32 burnRoot,
        uint64 count,
        uint64 lezHeight,
        bytes32 lezBlockHash,
        bytes calldata attestation
    ) external view;

    /// False for the interim verifier and for the option O committee verifier.
    function TRUSTLESS() external pure returns (bool);
}
