// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {Deploy} from "../script/Deploy.s.sol";
import {BridgeVault} from "../src/BridgeVault.sol";
import {EcdsaRootVerifier} from "../src/EcdsaRootVerifier.sol";

contract DeployScriptTest is Test {
    function test_Sec8_deployScriptAssertsVaultAddressAndRegisters() public {
        Deploy s = new Deploy();
        address deployer = DEFAULT_SENDER; // forge's default broadcaster
        address expected = s.predict(deployer);
        vm.setEnv("CONFIG_ID", vm.toString(keccak256("cfg")));
        vm.setEnv("SIGNER_1", vm.toString(address(0x1111)));
        vm.setEnv("SIGNER_2", vm.toString(address(0x2222)));
        vm.setEnv("MEMBERSHIP_IMAGE_ID", vm.toString(keccak256("image")));
        // one test: env vars are process-global, so a second test setting FREEZER would race this one
        vm.setEnv("FREEZER", vm.toString(deployer));
        vm.setEnv("EXPECTED_VAULT", vm.toString(expected));
        vm.expectRevert("FREEZER must not be the deployer (admin)");
        s.run();
        vm.stopBroadcast();

        vm.setEnv("FREEZER", vm.toString(address(0xf)));
        vm.setEnv("EXPECTED_VAULT", vm.toString(address(0xbad)));
        vm.expectRevert("vault address != EXPECTED_VAULT (nonce moved?)");
        s.run();
        vm.stopBroadcast(); // the reverted run left its broadcast open in the test VM

        vm.setEnv("EXPECTED_VAULT", vm.toString(expected));
        (address usdt, EcdsaRootVerifier ver, BridgeVault vault) = s.run();
        assertEq(address(vault), expected);
        assertEq(vault.CONFIG_ID(), keccak256("cfg"));
        assertEq(ver.CONFIG_ID(), keccak256("cfg"));
        assertEq(address(vault.ROOT_VERIFIER()), address(ver));
        assertEq(address(vault.GROTH16()), 0x2a098988600d87650Fb061FfAff08B97149Fa84D);
        assertEq(vault.MAX_FEE_BPS(), 500);
        assertEq(vault.owner(), deployer);
        assertEq(vault.FREEZER(), address(0xf));
        assertEq(vault.minLezDepth(), 10);
        (bool listed,, uint64 delay, uint64 window, uint128 dc, uint128 rc) = vault.tokens(usdt);
        assertTrue(listed);
        assertEq(delay, 600);
        assertEq(window, 1 days);
        assertEq(dc, 400e6);
        assertEq(rc, 200e6);
        (bool ok, uint128 fee) = vault.denoms(address(0), 0.01 ether);
        assertTrue(ok);
        assertEq(fee, 0.0001 ether);
        assertEq(vault.MIN_TIMELOCK(), 6 hours);
    }
}
