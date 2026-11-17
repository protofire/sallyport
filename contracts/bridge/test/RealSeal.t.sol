// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {IRiscZeroVerifier, VerificationFailed} from "risc0/IRiscZeroVerifier.sol";

/// Fork test against the pinned Sepolia RiscZeroGroth16Verifier v3.0.0 (never the router), with the real `burn_member` seal from the 2026-11-10 run. Skipped unless `SEPOLIA_RPC` is set (offline/CI runs do not depend on a public
/// RPC) and unless `test/fixtures/real_seal.json` exists:
/// { "imageId": "0x…", "journal": "0x…" (352 bytes), "seal": "0x…" } (camelCase keys).
contract RealSealTest is Test {
    address constant GROTH16 = 0x2a098988600d87650Fb061FfAff08B97149Fa84D;
    string constant FIXTURE = "test/fixtures/real_seal.json";
    /// burn_member ImageID of the reproducible Docker build (README table; vault MEMBERSHIP_IMAGE_ID on Sepolia).
    bytes32 constant BURN_MEMBER_IMAGE_ID = 0xb75588bcf980443c07957f005de58e9b811dd6f1b7d3795a26899785d78b5821;

    function test_B22_5_realSealOnSepoliaVerifier() public {
        string memory rpc = vm.envOr("SEPOLIA_RPC", string(""));
        if (bytes(rpc).length == 0 || !vm.exists(FIXTURE)) vm.skip(true);
        string memory j = vm.readFile(FIXTURE);
        bytes memory seal = vm.parseJsonBytes(j, ".seal");
        bytes32 image = vm.parseJsonBytes32(j, ".imageId");
        bytes memory journal = vm.parseJsonBytes(j, ".journal");
        assertEq(image, BURN_MEMBER_IMAGE_ID, "fixture imageId is not the Docker-built burn_member");
        assertEq(journal.length, 352);

        vm.createSelectFork(rpc);
        bytes32 digest = sha256(journal); // outside expectRevert: the sha256 precompile call would consume it
        uint256 g = gasleft();
        IRiscZeroVerifier(GROTH16).verify(seal, image, digest);
        emit log_named_uint("groth16 verify gas", g - gasleft());

        seal[seal.length - 1] ^= 0x01;
        vm.expectRevert(VerificationFailed.selector); // 0x439cc0cd
        IRiscZeroVerifier(GROTH16).verify(seal, image, digest);
    }
}
