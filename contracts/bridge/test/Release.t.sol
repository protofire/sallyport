// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {VerificationFailed} from "risc0/IRiscZeroVerifier.sol";
import {BridgeBase, IUSDT} from "./Base.t.sol";
import {BridgeVault} from "../src/BridgeVault.sol";

/// Recipient that re-enters `release` with a second valid proof when paid.
contract ReentrantRecipient {
    BridgeVault public vault;
    bytes public call_;

    function arm(BridgeVault v, bytes calldata c) external {
        vault = v;
        call_ = c;
    }

    receive() external payable {
        (bool ok, bytes memory ret) = address(vault).call(call_);
        if (!ok) {
            assembly {
                revert(add(ret, 32), mload(ret))
            }
        }
    }
}

contract ReleaseTest is BridgeBase {
    function setUp() public override {
        super.setUp();
        _fund(ETH, D_ETH, 4);
        _fund(usdt, D_USD, 4);
        _accept(ETH, D_ETH, "r");
        _accept(usdt, D_USD, "r");
    }

    function test_Sec2_unacceptedRootReverts() public {
        vm.warp(T0 + D);
        bytes memory s = _seal(usdt, D_USD, "nope", "nb", alice, 0);
        vm.expectRevert(BridgeVault.RootNotAccepted.selector);
        vault.release(usdt, D_USD, "nope", "nb", alice, relayer, 0, s);
    }

    function test_R3_releaseDelayInclusive() public {
        bytes memory s = _seal(usdt, D_USD, "r", "nb", alice, 0);
        vm.warp(T0 + D - 1);
        vm.expectRevert(BridgeVault.ReleaseTooEarly.selector);
        vault.release(usdt, D_USD, "r", "nb", alice, relayer, 0, s);
        vm.warp(T0 + D);
        vault.release(usdt, D_USD, "r", "nb", alice, relayer, 0, s);
    }

    function test_Sec5_freezeEachHalfIndependently() public {
        vm.warp(T0 + D);
        vm.prank(freezer);
        vault.setFrozen(true, false); // deposits frozen
        _release(usdt, D_USD, "r", "n1", alice, 0); // releases still work

        vm.prank(freezer);
        vault.setFrozen(false, true); // releases frozen
        _deposit(address(tok6), 100e6, "deposit still works"); // usdt window cap is full from setUp
        bytes memory s = _seal(usdt, D_USD, "r", "n2", alice, 0);
        vm.expectRevert(BridgeVault.Frozen.selector);
        vault.release(usdt, D_USD, "r", "n2", alice, relayer, 0, s);

        vm.prank(freezer);
        vault.setFrozen(false, false);
        vm.prank(freezer);
        vault.setTokenFrozen(usdt, false, true);
        vm.expectRevert(BridgeVault.Frozen.selector);
        vault.release(usdt, D_USD, "r", "n2", alice, relayer, 0, s);
        _release(ETH, D_ETH, "r", "n3", alice, 0); // other token unaffected
    }

    function test_Sec2_replayedNullifierReverts() public {
        vm.warp(T0 + D);
        _release(usdt, D_USD, "r", "nb", alice, 0);
        bytes memory s = _seal(usdt, D_USD, "r", "nb", alice, 0);
        vm.expectRevert(BridgeVault.NullifierSpent.selector);
        vault.release(usdt, D_USD, "r", "nb", alice, relayer, 0, s);
    }

    /// The seal binds every journal field: changing any one fails verification (Sec3: relayer cannot redirect).
    function test_Sec3_journalFieldsBound() public {
        _accept(usdt, D_USD, "r2");
        vm.prank(admin);
        vault.setDenom(usdt, 2 * D_USD, true, 0);
        vm.warp(T0 + D);
        uint256 fee = 1e6;
        bytes memory s = _seal(usdt, D_USD, "r", "nb", alice, fee);
        address eve = makeAddr("eve");

        vm.expectRevert(VerificationFailed.selector);
        vault.release(usdt, D_USD, "r", "nb", eve, relayer, fee, s); // recipient
        vm.expectRevert(VerificationFailed.selector);
        vault.release(usdt, D_USD, "r", "nb", alice, eve, fee, s); // relayer
        vm.expectRevert(VerificationFailed.selector);
        vault.release(usdt, D_USD, "r", "nb", alice, relayer, fee + 1, s); // fee
        vm.expectRevert(VerificationFailed.selector);
        vault.release(usdt, D_USD, "r2", "nb", alice, relayer, fee, s); // root
        vm.expectRevert(VerificationFailed.selector);
        vault.release(usdt, D_USD, "r", "nb2", alice, relayer, fee, s); // nullifier
        vm.expectRevert(BridgeVault.RootNotAccepted.selector);
        vault.release(usdt, 2 * D_USD, "r", "nb", alice, relayer, fee, s); // denom: root keyed by denom
        vm.expectRevert(BridgeVault.RootNotAccepted.selector);
        vault.release(address(tok6), D_USD, "r", "nb", alice, relayer, fee, s); // token: root keyed by token
        // same root accepted for another denom: the journal still binds the denom
        vault.acceptBurnRoot(
            usdt, 2 * D_USD, "r", 1, 100, bytes32(uint256(0xb10c)), _att(_digest(usdt, 2 * D_USD, "r", 1))
        );
        vm.warp(block.timestamp + D);
        vm.expectRevert(VerificationFailed.selector);
        vault.release(usdt, 2 * D_USD, "r", "nb", alice, relayer, fee, s);

        vault.release(usdt, D_USD, "r", "nb", alice, relayer, fee, s);
    }

    function test_Sec2_flippedSealReverts() public {
        vm.warp(T0 + D);
        bytes memory s = _seal(usdt, D_USD, "r", "nb", alice, 0);
        s[s.length - 1] ^= 0x01;
        vm.expectRevert(VerificationFailed.selector);
        vault.release(usdt, D_USD, "r", "nb", alice, relayer, 0, s);
        assertFalse(vault.spent("nb"));
    }

    function test_F13_feeAboveMaxReverts() public {
        vm.warp(T0 + D);
        uint256 max = D_USD * 500 / 10_000;
        bytes memory s = _seal(usdt, D_USD, "r", "nb", alice, max + 1);
        vm.expectRevert(BridgeVault.FeeTooHigh.selector);
        vault.release(usdt, D_USD, "r", "nb", alice, relayer, max + 1, s);
        _release(usdt, D_USD, "r", "nb", alice, max);
    }

    /// Admin timelock: a delay/window/cap change on a listed token takes effect only after the current
    /// releaseDelay, so admin + signers cannot set delay 0 / cap max and drain in one block.
    function test_Sec4_setTokenRiskParamsWaitCurrentDelay() public {
        vm.warp(T0 + D);
        vm.prank(admin);
        vault.setToken(usdt, BridgeVault.TokenConfig(true, true, 0, uint64(W), uint128(4 * D_USD), type(uint128).max));
        assertEq(vault.pendingTokenAt(usdt), T0 + 2 * D);
        // still the old cap (2·d) and the old delay for a root accepted now
        _release(usdt, D_USD, "r", "n1", alice, 0);
        _release(usdt, D_USD, "r", "n2", alice, 0);
        bytes memory s = _seal(usdt, D_USD, "r", "n3", alice, 0);
        vm.expectRevert(BridgeVault.CapExceeded.selector);
        vault.release(usdt, D_USD, "r", "n3", alice, relayer, 0, s);
        _accept(usdt, D_USD, "r2");
        bytes memory s2 = _seal(usdt, D_USD, "r2", "n4", alice, 0);
        vm.expectRevert(BridgeVault.ReleaseTooEarly.selector);
        vault.release(usdt, D_USD, "r2", "n4", alice, relayer, 0, s2);
        // after the current delay the queued values apply
        vm.warp(T0 + 2 * D);
        BridgeVault.TokenConfig memory ec = vault.effectiveToken(usdt);
        assertEq(ec.releaseDelay, 0);
        assertEq(ec.releaseCap, type(uint128).max);
        vault.release(usdt, D_USD, "r", "n3", alice, relayer, 0, s);
        // closing deposits stays immediate (a safety action)
        vm.prank(admin);
        vault.setToken(usdt, BridgeVault.TokenConfig(true, false, 0, uint64(W), uint128(4 * D_USD), 1));
        vm.prank(alice);
        vm.expectRevert(BridgeVault.DepositsClosed.selector);
        vault.deposit(usdt, D_USD, "late");
    }

    function test_F11_releaseCap() public {
        vm.warp(T0 + D);
        _release(usdt, D_USD, "r", "n1", alice, 0);
        _release(usdt, D_USD, "r", "n2", alice, 0);
        bytes memory s = _seal(usdt, D_USD, "r", "n3", alice, 0);
        vm.expectRevert(BridgeVault.CapExceeded.selector);
        vault.release(usdt, D_USD, "r", "n3", alice, relayer, 0, s);
    }

    function test_F1_exactPayoutEth() public {
        address to = makeAddr("recipient_j");
        vm.warp(T0 + D);
        uint256 fee = D_ETH / 100;
        _release(ETH, D_ETH, "r", "nb", to, fee);
        assertEq(to.balance, D_ETH - fee);
        assertEq(relayer.balance, fee);
        assertEq(address(vault).balance, 3 * D_ETH);
    }

    function test_F17_exactPayoutTether() public {
        address to = makeAddr("recipient_j");
        vm.warp(T0 + D);
        uint256 fee = D_USD / 100;
        _release(usdt, D_USD, "r", "nb", to, fee);
        assertEq(IUSDT(usdt).balanceOf(to), D_USD - fee);
        assertEq(IUSDT(usdt).balanceOf(relayer), fee);
        assertEq(IUSDT(usdt).balanceOf(address(vault)), 3 * D_USD);
    }

    function test_F13_adminFeeChangeAfterProvingLeavesPayout() public {
        address to = makeAddr("recipient_j");
        uint256 fee = D_USD / 100; // standard fee at proving time
        bytes memory s = _seal(usdt, D_USD, "r", "nb", to, fee);
        vm.prank(admin);
        vault.setDenom(usdt, D_USD, true, uint128(D_USD / 50)); // admin doubles the standard fee
        vm.warp(T0 + D);
        vault.release(usdt, D_USD, "r", "nb", to, relayer, fee, s);
        assertEq(IUSDT(usdt).balanceOf(to), D_USD - fee);
        assertEq(IUSDT(usdt).balanceOf(relayer), fee);
    }

    function test_Sec2_reentrantEthRecipient() public {
        ReentrantRecipient bad = new ReentrantRecipient();
        vm.warp(T0 + D);
        bytes memory inner = abi.encodeCall(
            BridgeVault.release,
            (ETH, D_ETH, "r", "n2", address(bad), relayer, 0, _seal(ETH, D_ETH, "r", "n2", address(bad), 0))
        );
        bad.arm(vault, inner);
        bytes memory s = _seal(ETH, D_ETH, "r", "n1", address(bad), 0);
        vm.expectRevert(); // ReentrancyGuardReentrantCall, bubbled through sendValue
        vault.release(ETH, D_ETH, "r", "n1", address(bad), relayer, 0, s);
        assertEq(address(bad).balance, 0);
        assertFalse(vault.spent("n1"));
        assertFalse(vault.spent("n2"));
    }

    /// Sec8: no setter for any verifier, image id, signer, config id or fee bound.
    function test_Sec8_noVerificationSetters() public view {
        string[5] memory allowed = ["setToken", "setDenom", "setMinLezDepth", "setFrozen", "setTokenFrozen"];
        string[] memory fns =
            vm.parseJsonKeys(vm.readFile("out/BridgeVault.sol/BridgeVault.json"), ".methodIdentifiers");
        for (uint256 i = 0; i < fns.length; i++) {
            bytes memory f = bytes(fns[i]);
            if (f.length < 3 || f[0] != "s" || f[1] != "e" || f[2] != "t") continue;
            bool ok;
            for (uint256 k = 0; k < allowed.length; k++) {
                ok = ok || _startsWith(fns[i], string.concat(allowed[k], "("));
            }
            assertTrue(ok, fns[i]);
        }
        fns = vm.parseJsonKeys(vm.readFile("out/EcdsaRootVerifier.sol/EcdsaRootVerifier.json"), ".methodIdentifiers");
        for (uint256 i = 0; i < fns.length; i++) {
            assertFalse(_startsWith(fns[i], "set"), fns[i]);
        }
    }

    function _startsWith(string memory s, string memory p) internal pure returns (bool) {
        bytes memory a = bytes(s);
        bytes memory b = bytes(p);
        if (a.length < b.length) return false;
        for (uint256 i = 0; i < b.length; i++) {
            if (a[i] != b[i]) return false;
        }
        return true;
    }
}
