// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {RiscZeroMockVerifier} from "risc0/test/RiscZeroMockVerifier.sol";
import {BridgeVault} from "../src/BridgeVault.sol";
import {EcdsaRootVerifier} from "../src/EcdsaRootVerifier.sol";
import {IBurnRootVerifier} from "../src/IBurnRootVerifier.sol";
import {FeeOnTransferToken} from "./mocks/FeeOnTransferToken.sol";

/// Cross-language known answers: fixtures/b22/vectors.json is written by crates/bridge-core.
contract VectorsTest is Test {
    string json;

    function setUp() public {
        json = vm.readFile("../../fixtures/b22/vectors.json");
    }

    function _b32(string memory key) internal view returns (bytes32) {
        return vm.parseBytes32(string.concat("0x", vm.parseJsonString(json, key)));
    }

    function _addr(string memory key) internal view returns (address) {
        return vm.parseAddress(string.concat("0x", vm.parseJsonString(json, key)));
    }

    function _bytes(string memory key) internal view returns (bytes memory) {
        return vm.parseBytes(string.concat("0x", vm.parseJsonString(json, key)));
    }

    function _uintStr(string memory key) internal view returns (uint256) {
        return vm.parseUint(vm.parseJsonString(json, key));
    }

    function test_F15_eventTopicsAndTags() public view {
        assertEq(BridgeVault.Deposit.selector, _b32(".constants.deposit_topic0"));
        assertEq(keccak256("Deposit(bytes32,address,bytes32,uint256)"), _b32(".constants.deposit_topic0"));
        assertEq(_b32(".inputs.bridge_config.deposit_topic0"), _b32(".constants.deposit_topic0"));
        assertEq(BridgeVault.BurnRootAccepted.selector, _b32(".constants.burn_root_accepted_topic0"));
        assertEq(BridgeVault.BurnRootRevoked.selector, _b32(".constants.burn_root_revoked_topic0"));
        assertEq(bytes32("b022/rel/v1"), _b32(".constants.tag_rel"));
        assertEq(bytes32("b022/root/v1"), _b32(".constants.tag_root"));
    }

    // vector inputs, loaded in setUp (storage keeps the test bodies under the stack limit)
    bytes32 cfg;
    address vaultAddr;
    address token;
    uint256 d;
    bytes32 root;
    uint64 count;
    uint64 height;
    bytes32 bh;
    uint256 fee;
    bytes32 nb;
    address recipient;
    address relayer;
    bytes32 image = keccak256("image");
    uint256 k1;
    uint256 k2;
    EcdsaRootVerifier ver;
    RiscZeroMockVerifier groth;
    BridgeVault vault;

    function _load() internal {
        cfg = _b32(".config.config_id");
        vaultAddr = _addr(".inputs.bridge_config.vault");
        token = _addr(".inputs.token");
        d = _uintStr(".inputs.denom");
        root = _b32(".root_attestation.burn_root");
        count = uint64(vm.parseJsonUint(json, ".root_attestation.count"));
        height = uint64(vm.parseJsonUint(json, ".inputs.lez_height"));
        bh = _b32(".inputs.lez_block_hash");
        fee = _uintStr(".inputs.fee");
        nb = _b32(".per_index[0].nb");
        recipient = _addr(".per_index[0].recipient");
        relayer = _addr(".inputs.relayer");
        vm.chainId(vm.parseJsonUint(json, ".inputs.bridge_config.evm_chain_id"));

        address s1;
        address s2;
        (s1, k1) = makeAddrAndKey("v1");
        (s2, k2) = makeAddrAndKey("v2");
        if (s2 < s1) (s1, s2, k1, k2) = (s2, s1, k2, k1);
        address[] memory signers = new address[](2);
        signers[0] = s1;
        signers[1] = s2;
        ver = new EcdsaRootVerifier(signers, 2, cfg);
        groth = new RiscZeroMockVerifier(bytes4(0xb22b22b2));
        deployCodeTo(
            "BridgeVault.sol:BridgeVault",
            abi.encode(
                address(this), address(0xf), IBurnRootVerifier(ver), groth, image, cfg, uint256(500), uint256(600)
            ),
            vaultAddr
        );
        vault = BridgeVault(payable(vaultAddr));
    }

    /// Root digest and release journal (352 bytes) + sha256 at the vector's vault address and chain id.
    function test_F15_rootDigestAndJournal() public {
        _load();
        assertEq(ver.rootDigest(vaultAddr, token, d, root, count, height, bh), _b32(".root_attestation.digest"));
        bytes memory j = vault.releaseJournal(token, d, root, nb, recipient, relayer, fee);
        assertEq(j.length, 352);
        assertEq(j, _bytes(".release_journal.abi"), "journal");
        assertEq(sha256(j), _b32(".release_journal.sha256"), "journal sha256");
    }

    /// End to end on the vector values: deposit emits the vector topics; accept with the vector digest;
    /// release with a mock seal keyed on the vector journal sha256.
    function test_F15_vectorRoundTrip() public {
        _load();
        deployCodeTo("FeeOnTransferToken.sol:FeeOnTransferToken", abi.encode(uint8(6), uint256(0)), token);
        FeeOnTransferToken(token).mint(address(this), d);
        FeeOnTransferToken(token).approve(vaultAddr, d);
        vault.setToken(token, BridgeVault.TokenConfig(true, true, 600, 1 days, uint128(4 * d), uint128(2 * d)));
        vault.setDenom(token, d, true, uint128(fee));

        bytes32 c = _b32(".per_index[0].commitment");
        vm.recordLogs();
        vault.deposit(token, d, c);
        bytes32[] memory topics = vm.getRecordedLogs()[1].topics; // [0] = the token Transfer
        assertEq(topics[0], _b32(".constants.deposit_topic0"));
        assertEq(topics[1], c);
        assertEq(topics[2], bytes32(uint256(uint160(token))));
        assertEq(topics[3], cfg);

        bytes32 digest = _b32(".root_attestation.digest");
        (uint8 v1, bytes32 r1, bytes32 x1) = vm.sign(k1, digest);
        (uint8 v2, bytes32 r2, bytes32 x2) = vm.sign(k2, digest);
        vault.acceptBurnRoot(token, d, root, count, height, bh, abi.encodePacked(r1, x1, v1, r2, x2, v2));
        vm.warp(block.timestamp + 600);
        bytes memory seal = groth.mockProve(image, _b32(".release_journal.sha256")).seal;
        vault.release(token, d, root, nb, recipient, relayer, fee, seal);
        assertEq(FeeOnTransferToken(token).balanceOf(recipient), d - fee);
        assertEq(FeeOnTransferToken(token).balanceOf(relayer), fee);
    }
}
