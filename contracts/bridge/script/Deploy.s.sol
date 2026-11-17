// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {Script, console} from "forge-std/Script.sol";
import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";
import {BridgeVault} from "../src/BridgeVault.sol";
import {EcdsaRootVerifier} from "../src/EcdsaRootVerifier.sol";

/// RFP-022 Sepolia deploy (order of docs/ARCHITECTURE.md §3.2): [TetherToken mock] → EcdsaRootVerifier → BridgeVault, then the
/// demo registration (see contracts/bridge/README.md). The vault address must be precomputed (`predict`) because CONFIG_ID binds it.
///
/// 1. forge script script/Deploy.s.sol --sig "predict(address)" <deployer> --rpc-url $SEPOLIA_RPC
/// 2. compute cfg (bridge-core) with that vault address and L2's bridge_program_id
/// 3. CONFIG_ID=… SIGNER_1=… SIGNER_2=… MEMBERSHIP_IMAGE_ID=… EXPECTED_VAULT=… FREEZER=… \
///    forge script script/Deploy.s.sol --rpc-url $SEPOLIA_RPC --broadcast --private-key $SEPOLIA_KEY
/// Optional: GROTH16 (default the pinned v3.0.0 verifier, never the router), USDT (reuse a deployed mock),
/// MIN_TIMELOCK (seconds, default 6 h, bounds 10 min..30 days: floor on the queue time of a loosening `setToken`).
/// FREEZER must differ from the deployer (the vault admin).
contract Deploy is Script {
    address constant GROTH16_V3 = 0x2a098988600d87650Fb061FfAff08B97149Fa84D;
    uint256 constant MAX_FEE_BPS = 500;
    uint64 constant RELEASE_DELAY = 600;
    uint64 constant WINDOW = 24 hours;
    uint64 constant MIN_LEZ_DEPTH = 10;
    uint256 constant D_ETH = 0.01 ether;
    uint256 constant D_USDT = 100e6;

    /// Address the vault will get when `deployer` runs `run()` next.
    function predict(address deployer) public view returns (address vault) {
        bool mock = vm.envOr("USDT", address(0)) == address(0);
        vault = vm.computeCreateAddress(deployer, vm.getNonce(deployer) + (mock ? 2 : 1));
        console.log("expected vault", vault);
    }

    function run() external returns (address usdt, EcdsaRootVerifier verifier, BridgeVault vault) {
        bytes32 cfg = vm.envBytes32("CONFIG_ID");
        address[] memory signers = new address[](2);
        signers[0] = vm.envAddress("SIGNER_1");
        signers[1] = vm.envAddress("SIGNER_2");
        bytes32 image = vm.envBytes32("MEMBERSHIP_IMAGE_ID");
        address expected = vm.envAddress("EXPECTED_VAULT");
        address freezer = vm.envAddress("FREEZER");
        address groth16 = vm.envOr("GROTH16", GROTH16_V3);
        uint256 minTimelock = vm.envOr("MIN_TIMELOCK", uint256(6 hours));
        usdt = vm.envOr("USDT", address(0));

        vm.startBroadcast();
        (, address deployer,) = vm.readCallers();
        require(freezer != deployer, "FREEZER must not be the deployer (admin)");
        require(predict(deployer) == expected, "vault address != EXPECTED_VAULT (nonce moved?)");
        if (usdt == address(0)) {
            usdt = deployCode(
                "out/TetherToken.sol/TetherToken.json",
                abi.encode(uint256(1e12), "Tether USD (b22 mock)", "USDT", uint256(6))
            );
        }
        verifier = new EcdsaRootVerifier(signers, 2, cfg);
        vault = new BridgeVault(
            deployer, freezer, verifier, IRiscZeroVerifier(groth16), image, cfg, MAX_FEE_BPS, minTimelock
        );
        require(address(vault) == expected, "vault landed at another address");

        _register(vault, address(0), D_ETH);
        _register(vault, usdt, D_USDT);
        vault.setMinLezDepth(MIN_LEZ_DEPTH);
        vm.stopBroadcast();

        console.log("usdt mock", usdt);
        console.log("EcdsaRootVerifier (INTERIM, CUSTODIAL)", address(verifier));
        console.log("BridgeVault", address(vault));
    }

    /// Demo parameters: delay 600 s, fixed 24 h windows, deposit cap 4·d, release cap 2·d, standard fee 1%.
    function _register(BridgeVault vault, address token, uint256 d) internal {
        vault.setToken(
            token,
            BridgeVault.TokenConfig({
                listed: true,
                depositsOpen: true,
                releaseDelay: RELEASE_DELAY,
                window: WINDOW,
                depositCap: uint128(4 * d),
                releaseCap: uint128(2 * d)
            })
        );
        vault.setDenom(token, d, true, uint128(d / 100));
    }
}
