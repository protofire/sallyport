// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {BridgeBase} from "./Base.t.sol";
import {BridgeVault} from "../src/BridgeVault.sol";

/// Admin timelock on token risk parameters (docs/ARCHITECTURE.md §3.7): loosening waits max(current delay, MIN_TIMELOCK) and the
/// freezer can cancel it; tightening applies at once; the cap window is fixed at listing.
contract TimelockTest is BridgeBase {
    function _cfg(uint64 delay, uint128 dc, uint128 rc) internal pure returns (BridgeVault.TokenConfig memory) {
        return BridgeVault.TokenConfig(true, true, delay, uint64(W), dc, rc);
    }

    function test_Sec4_constructorRejectsFreezerEqualsAdminAndZeroTimelock() public {
        vm.expectRevert(BridgeVault.BadParam.selector);
        new BridgeVault(admin, admin, verifier, groth, IMAGE, CFG, 500, MIN_TL);
        vm.expectRevert(BridgeVault.BadParam.selector);
        new BridgeVault(admin, freezer, verifier, groth, IMAGE, CFG, 500, 0);
    }

    function test_Sec4_freezerCancelsQueuedChange() public {
        vm.prank(admin);
        vault.setToken(usdt, _cfg(0, uint128(4 * D_USD), type(uint128).max));
        assertEq(vault.pendingTokenAt(usdt), T0 + D);
        vm.prank(admin);
        vm.expectRevert(BridgeVault.NotFreezer.selector);
        vault.cancelTokenChange(usdt);
        vm.prank(freezer);
        vault.cancelTokenChange(usdt);
        assertEq(vault.pendingTokenAt(usdt), 0);
        vm.warp(T0 + 10 * D);
        BridgeVault.TokenConfig memory ec = vault.effectiveToken(usdt);
        assertEq(ec.releaseDelay, D);
        assertEq(ec.releaseCap, 2 * D_USD);
        // nothing queued (or already matured) → nothing to cancel
        vm.prank(freezer);
        vm.expectRevert(BridgeVault.BadParam.selector);
        vault.cancelTokenChange(usdt);
    }

    function test_Sec4_maturedChangeCannotBeCancelled() public {
        vm.prank(admin);
        vault.setToken(usdt, _cfg(D, uint128(4 * D_USD), uint128(3 * D_USD)));
        vm.warp(T0 + D);
        vm.prank(freezer);
        vm.expectRevert(BridgeVault.BadParam.selector);
        vault.cancelTokenChange(usdt);
        assertEq(vault.effectiveToken(usdt).releaseCap, 3 * D_USD);
    }

    /// A token listed with delay 0 still gets MIN_TIMELOCK before a loosening applies.
    function test_Sec4_minTimelockFloor() public {
        address t = makeAddr("fresh token");
        vm.startPrank(admin);
        vault.setToken(t, BridgeVault.TokenConfig(true, true, 0, uint64(W), 1, 1)); // first listing: at once
        vault.setToken(t, BridgeVault.TokenConfig(true, true, 0, uint64(W), 1, type(uint128).max));
        vm.stopPrank();
        assertEq(vault.pendingTokenAt(t), T0 + MIN_TL);
        assertEq(vault.effectiveToken(t).releaseCap, 1);
        vm.warp(T0 + MIN_TL);
        assertEq(vault.effectiveToken(t).releaseCap, type(uint128).max);
    }

    function test_Sec4_tighteningAppliesAtOnceAndDropsQueuedLoosening() public {
        vm.startPrank(admin);
        vault.setToken(usdt, _cfg(0, uint128(4 * D_USD), type(uint128).max)); // loosening, queued
        vault.setToken(usdt, _cfg(2 * D, uint128(D_USD), uint128(D_USD))); // tightening
        vm.stopPrank();
        assertEq(vault.pendingTokenAt(usdt), 0);
        BridgeVault.TokenConfig memory ec = vault.effectiveToken(usdt);
        assertEq(ec.releaseDelay, 2 * D);
        assertEq(ec.releaseCap, D_USD);
        (,, uint64 delay,,, uint128 rc) = vault.tokens(usdt);
        assertEq(delay, 2 * D);
        assertEq(rc, D_USD);
        vm.warp(T0 + 10 * D);
        assertEq(vault.effectiveToken(usdt).releaseCap, D_USD);
    }

    /// Raising one cap while lowering another is a loosening: queued as a whole.
    function test_Sec4_mixedChangeIsQueued() public {
        vm.prank(admin);
        vault.setToken(usdt, _cfg(D, uint128(D_USD), uint128(3 * D_USD)));
        assertEq(vault.pendingTokenAt(usdt), T0 + D);
        assertEq(vault.effectiveToken(usdt).depositCap, 4 * D_USD);
    }

    function test_Sec4_windowFixedAfterListing() public {
        vm.prank(admin);
        vm.expectRevert(BridgeVault.BadParam.selector);
        vault.setToken(usdt, BridgeVault.TokenConfig(true, true, D, uint64(2 * W), uint128(4 * D_USD), 1));
    }

    /// A tightening applies at once, so the delay needs an upper bound: uint64.max would lock the escrow forever.
    function test_Sec4_releaseDelayBoundedByMaxDelay() public {
        uint64 max = uint64(vault.MAX_DELAY());
        vm.startPrank(admin);
        vm.expectRevert(BridgeVault.BadParam.selector);
        vault.setToken(usdt, _cfg(type(uint64).max, uint128(4 * D_USD), uint128(2 * D_USD)));
        vm.expectRevert(BridgeVault.BadParam.selector);
        vault.setToken(usdt, _cfg(max + 1, uint128(4 * D_USD), uint128(2 * D_USD)));
        vault.setToken(usdt, _cfg(max, uint128(4 * D_USD), uint128(2 * D_USD))); // tightening, at once
        vm.expectRevert(BridgeVault.BadParam.selector); // first listing is bounded too
        vault.setToken(makeAddr("fresh"), BridgeVault.TokenConfig(true, true, max + 1, uint64(W), 1, 1));
        vm.stopPrank();
        assertEq(vault.effectiveToken(usdt).releaseDelay, max);
        // the lock of a later loosening is bounded by max(MAX_DELAY, MIN_TIMELOCK)
        vm.prank(admin);
        vault.setToken(usdt, _cfg(D, uint128(4 * D_USD), uint128(2 * D_USD)));
        assertEq(vault.pendingTokenAt(usdt), T0 + max);
    }

    function test_Sec4_requeueAfterCancel() public {
        vm.prank(admin);
        vault.setToken(usdt, _cfg(D, uint128(4 * D_USD), uint128(3 * D_USD)));
        vm.prank(freezer);
        vault.cancelTokenChange(usdt);
        vm.warp(T0 + 1);
        vm.prank(admin);
        vault.setToken(usdt, _cfg(D, uint128(4 * D_USD), uint128(3 * D_USD)));
        assertEq(vault.pendingTokenAt(usdt), T0 + 1 + D);
        vm.warp(T0 + 1 + D);
        assertEq(vault.effectiveToken(usdt).releaseCap, 3 * D_USD);
    }

    function test_Sec4_constructorBoundsMinTimelock() public {
        vm.expectRevert(BridgeVault.BadParam.selector);
        new BridgeVault(admin, freezer, verifier, groth, IMAGE, CFG, 500, 10 minutes - 1);
        vm.expectRevert(BridgeVault.BadParam.selector);
        new BridgeVault(admin, freezer, verifier, groth, IMAGE, CFG, 500, 30 days + 1);
        new BridgeVault(admin, freezer, verifier, groth, IMAGE, CFG, 500, 10 minutes);
        new BridgeVault(admin, freezer, verifier, groth, IMAGE, CFG, 500, 30 days);
    }

    /// minLezDepth: an increase applies at once; a decrease waits MIN_TIMELOCK (signers read the effective value).
    function test_Sec4_minLezDepthDecreaseIsQueued() public {
        vm.startPrank(admin);
        vault.setMinLezDepth(10);
        assertEq(vault.effectiveMinLezDepth(), 10);
        vault.setMinLezDepth(2);
        vm.stopPrank();
        assertEq(vault.effectiveMinLezDepth(), 10);
        assertEq(vault.pendingMinLezDepthAt(), T0 + MIN_TL);
        vm.warp(T0 + MIN_TL);
        assertEq(vault.effectiveMinLezDepth(), 2);
        vm.prank(admin);
        vault.setMinLezDepth(20); // increase: at once, drops nothing pending
        assertEq(vault.effectiveMinLezDepth(), 20);
        assertEq(vault.pendingMinLezDepthAt(), 0);
    }
}
