// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {BridgeBase} from "./Base.t.sol";
import {BridgeVault} from "../src/BridgeVault.sol";

contract RevocationTest is BridgeBase {
    event BurnRootRevoked(address indexed token, uint256 indexed denom, bytes32 indexed burnRoot);

    function setUp() public override {
        super.setUp();
        _fund(usdt, D_USD, 4);
        _accept(usdt, D_USD, "r1");
    }

    function _revoke(bytes32 root) internal {
        vm.prank(freezer);
        vault.revokeRoot(usdt, D_USD, root);
    }

    function test_F14_revokeBeforeMaturityBlocksForever() public {
        vm.expectEmit(true, true, true, true, address(vault));
        emit BurnRootRevoked(usdt, D_USD, "r1");
        _revoke("r1");
        vm.warp(T0 + D);
        bytes memory s = _seal(usdt, D_USD, "r1", "nb", alice, 0);
        vm.expectRevert(BridgeVault.RootRevoked.selector);
        vault.release(usdt, D_USD, "r1", "nb", alice, relayer, 0, s);
        vm.warp(T0 + 365 days);
        vm.expectRevert(BridgeVault.RootRevoked.selector);
        vault.release(usdt, D_USD, "r1", "nb", alice, relayer, 0, s);
    }

    function test_F14_revokeAfterMaturityBlocks() public {
        vm.warp(T0 + D + 1);
        _revoke("r1");
        bytes memory s = _seal(usdt, D_USD, "r1", "nb", alice, 0);
        vm.expectRevert(BridgeVault.RootRevoked.selector);
        vault.release(usdt, D_USD, "r1", "nb", alice, relayer, 0, s);
    }

    function test_F14_revokedRootCannotBeReaccepted() public {
        _revoke("r1");
        bytes memory att = _att(_digest(usdt, D_USD, "r1", 1));
        vm.expectRevert(BridgeVault.RootAlreadyAccepted.selector);
        vault.acceptBurnRoot(usdt, D_USD, "r1", 1, 100, bytes32(uint256(0xb10c)), att);
        assertEq(vault.acceptedAt(usdt, D_USD, "r1"), vault.REVOKED());
        // pre-emptive revocation of a root never seen also blocks it
        _revoke("r9");
        att = _att(_digest(usdt, D_USD, "r9", 1));
        vm.expectRevert(BridgeVault.RootAlreadyAccepted.selector);
        vault.acceptBurnRoot(usdt, D_USD, "r9", 1, 100, bytes32(uint256(0xb10c)), att);
    }

    function test_F14_honestBurnReleasesUnderLaterRoot() public {
        _revoke("r1");
        vm.warp(T0 + 10);
        _accept(usdt, D_USD, "r2");
        vm.warp(T0 + 10 + D);
        _release(usdt, D_USD, "r2", "nb", alice, 0);
        assertTrue(vault.spent("nb"));
    }

    function test_F14_adminCannotRevoke() public {
        vm.prank(admin);
        vm.expectRevert(BridgeVault.NotFreezer.selector);
        vault.revokeRoot(usdt, D_USD, "r1");
    }

    function test_F14_spentNullifiersStaySpentAfterRevocation() public {
        vm.warp(T0 + D);
        _release(usdt, D_USD, "r1", "nb", alice, 0);
        _revoke("r1");
        _accept(usdt, D_USD, "r2");
        vm.warp(block.timestamp + D);
        bytes memory s = _seal(usdt, D_USD, "r2", "nb", alice, 0);
        vm.expectRevert(BridgeVault.NullifierSpent.selector);
        vault.release(usdt, D_USD, "r2", "nb", alice, relayer, 0, s);
    }

    /// Same block.timestamp, sequential calls = block order (docs/ARCHITECTURE.md §3.6).
    function test_Sec4_freezeThenReleaseSameBlock() public {
        vm.warp(T0 + D);
        vm.prank(freezer);
        vault.setTokenFrozen(usdt, false, true);
        bytes memory s = _seal(usdt, D_USD, "r1", "nb", alice, 0);
        vm.expectRevert(BridgeVault.Frozen.selector);
        vault.release(usdt, D_USD, "r1", "nb", alice, relayer, 0, s);
    }

    function test_Sec4_releaseThenFreezeSameBlock() public {
        vm.warp(T0 + D);
        _release(usdt, D_USD, "r1", "nb", alice, 0);
        vm.prank(freezer);
        vault.setTokenFrozen(usdt, false, true);
        assertTrue(vault.spent("nb"));
    }

    function test_Sec4_revokeThenReleaseSameBlock() public {
        vm.warp(T0 + D);
        _revoke("r1");
        bytes memory s = _seal(usdt, D_USD, "r1", "nb", alice, 0);
        vm.expectRevert(BridgeVault.RootRevoked.selector);
        vault.release(usdt, D_USD, "r1", "nb", alice, relayer, 0, s);
    }

    function test_Sec4_releaseThenRevokeSameBlock() public {
        vm.warp(T0 + D);
        _release(usdt, D_USD, "r1", "nb", alice, 0);
        _revoke("r1");
        assertTrue(vault.spent("nb"));
    }
}
