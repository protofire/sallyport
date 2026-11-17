// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IBurnRootVerifier} from "./IBurnRootVerifier.sol";

/// @title EcdsaRootVerifier — INTERIM, CUSTODIAL, NOT TRUSTLESS
/// @notice t-of-n secp256k1 signers attest LEZ burn roots. Whoever holds THRESHOLD signer keys can forge a root
///         and drain the escrow of every token of the vault, bounded only by the vault's release delay, caps and
///         the freezer's permanent root revocation (docs/ARCHITECTURE.md §3.7). The signer set and threshold are fixed at
///         construction: there is no setter and no rotation. Replaced by a new deployment behind
///         `IBurnRootVerifier` (docs/ARCHITECTURE.md §3.6), never upgraded in place.
/// @dev Each signer signs the raw digest (no EIP-191 prefix):
///      keccak256(abi.encode(TAG_ROOT, chainid, vault, CONFIG_ID, token, denom, burnRoot, count, lezHeight,
///      lezBlockHash)). `attestation` is THRESHOLD concatenated 65-byte (r, s, v) signatures whose recovered
///      addresses are configured signers in strictly ascending order; OZ ECDSA rejects high-s.
contract EcdsaRootVerifier is IBurnRootVerifier {
    bytes32 public constant TAG_ROOT = bytes32("b022/root/v1");

    bytes32 public immutable CONFIG_ID;
    uint256 public immutable THRESHOLD;

    mapping(address => bool) public isSigner;
    address[] private _signers;

    error BadThreshold();
    error BadSigner(address signer);
    error BadAttestationLength(uint256 length);
    error NotASigner(address recovered);
    error SignersNotAscending();

    constructor(address[] memory signers_, uint256 threshold, bytes32 configId) {
        if (threshold == 0 || threshold > signers_.length) revert BadThreshold();
        for (uint256 i = 0; i < signers_.length; i++) {
            address s = signers_[i];
            if (s == address(0) || isSigner[s]) revert BadSigner(s);
            isSigner[s] = true;
        }
        _signers = signers_;
        THRESHOLD = threshold;
        CONFIG_ID = configId;
    }

    /// @notice INTERIM, CUSTODIAL: always false.
    function TRUSTLESS() external pure returns (bool) {
        return false;
    }

    function signers() external view returns (address[] memory) {
        return _signers;
    }

    /// @notice The digest each signer signs for `vault` on this chain.
    function rootDigest(
        address vault,
        address token,
        uint256 denom,
        bytes32 burnRoot,
        uint64 count,
        uint64 lezHeight,
        bytes32 lezBlockHash
    ) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                TAG_ROOT, block.chainid, vault, CONFIG_ID, token, denom, burnRoot, count, lezHeight, lezBlockHash
            )
        );
    }

    /// @inheritdoc IBurnRootVerifier
    function verifyRoot(
        address token,
        uint256 denom,
        bytes32 burnRoot,
        uint64 count,
        uint64 lezHeight,
        bytes32 lezBlockHash,
        bytes calldata attestation
    ) external view {
        if (attestation.length != THRESHOLD * 65) revert BadAttestationLength(attestation.length);
        bytes32 digest = rootDigest(msg.sender, token, denom, burnRoot, count, lezHeight, lezBlockHash);
        address last;
        for (uint256 i = 0; i < THRESHOLD; i++) {
            address s = ECDSA.recoverCalldata(digest, attestation[i * 65:(i + 1) * 65]);
            if (!isSigner[s]) revert NotASigner(s);
            if (s <= last) revert SignersNotAscending();
            last = s;
        }
    }
}
