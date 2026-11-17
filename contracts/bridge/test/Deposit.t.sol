// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {BridgeBase, IUSDT} from "./Base.t.sol";
import {BridgeVault} from "../src/BridgeVault.sol";

contract DepositTest is BridgeBase {
    event Deposit(bytes32 indexed commitment, address indexed token, bytes32 indexed configId, uint256 amount);

    function test_F1_depositEthExactValue() public {
        _deposit(ETH, D_ETH, "c1");
        assertEq(address(vault).balance, D_ETH);
        assertTrue(vault.seen("c1"));

        vm.startPrank(alice);
        vm.expectRevert(BridgeVault.BadValue.selector);
        vault.deposit{value: D_ETH - 1}(ETH, D_ETH, "c2");
        vm.expectRevert(BridgeVault.BadValue.selector);
        vault.deposit{value: D_ETH + 1}(ETH, D_ETH, "c2");
        vm.expectRevert(BridgeVault.BadValue.selector);
        vault.deposit{value: 1}(address(tok6), 100e6, "c2");
        vm.stopPrank();
    }

    function test_F1_depositErc20SixAndEighteenDecimals() public {
        _deposit(address(tok6), 100e6, "c6");
        _deposit(address(tok18), 1e18, "c18");
        assertEq(tok6.balanceOf(address(vault)), 100e6);
        assertEq(tok18.balanceOf(address(vault)), 1e18);
    }

    function test_F17_depositTetherNoReturn() public {
        uint256 before = IUSDT(usdt).balanceOf(alice);
        _deposit(usdt, D_USD, "cu");
        assertEq(IUSDT(usdt).balanceOf(address(vault)), D_USD);
        assertEq(IUSDT(usdt).balanceOf(alice), before - D_USD);
    }

    function test_F1_feeOnTransferTokenReverts() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(BridgeVault.AmountMismatch.selector, 0.99e18));
        vault.deposit(address(fot), 1e18, "cf");
        assertFalse(vault.seen("cf"));
    }

    function test_F17_tetherWithFeeParamsReverts() public {
        IUSDT(usdt).setParams(10, 10); // 0.1% fee, as USDT can switch on
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(BridgeVault.AmountMismatch.selector, D_USD - D_USD / 1000));
        vault.deposit(usdt, D_USD, "cu");
    }

    function test_Sec2_unlistedTokenReverts() public {
        vm.prank(alice);
        vm.expectRevert(BridgeVault.TokenNotListed.selector);
        vault.deposit(address(0xdead), 1, "c");
    }

    function test_F8_wrongDenomReverts() public {
        vm.prank(alice);
        vm.expectRevert(BridgeVault.DenomNotPermitted.selector);
        vault.deposit{value: 2 * D_ETH}(ETH, 2 * D_ETH, "c");
        vm.prank(admin);
        vault.setDenom(ETH, D_ETH, false, 0);
        vm.prank(alice);
        vm.expectRevert(BridgeVault.DenomNotPermitted.selector);
        vault.deposit{value: D_ETH}(ETH, D_ETH, "c");
    }

    function test_F10_depositsClosedReverts() public {
        (bool listed,, uint64 delay, uint64 window, uint128 dc, uint128 rc) = vault.tokens(ETH);
        vm.prank(admin);
        vault.setToken(ETH, BridgeVault.TokenConfig(listed, false, delay, window, dc, rc));
        vm.prank(alice);
        vm.expectRevert(BridgeVault.DepositsClosed.selector);
        vault.deposit{value: D_ETH}(ETH, D_ETH, "c");
    }

    function test_F14_depositFrozenGlobalAndPerToken() public {
        vm.prank(freezer);
        vault.setFrozen(true, false);
        vm.prank(alice);
        vm.expectRevert(BridgeVault.Frozen.selector);
        vault.deposit{value: D_ETH}(ETH, D_ETH, "c");

        vm.startPrank(freezer);
        vault.setFrozen(false, false);
        vault.setTokenFrozen(ETH, true, false);
        vm.stopPrank();
        vm.prank(alice);
        vm.expectRevert(BridgeVault.Frozen.selector);
        vault.deposit{value: D_ETH}(ETH, D_ETH, "c");
        _deposit(usdt, D_USD, "other token unaffected");

        vm.prank(freezer);
        vault.setTokenFrozen(ETH, false, false);
        _deposit(ETH, D_ETH, "c");
    }

    function test_F14_onlyFreezerFreezes() public {
        vm.prank(admin);
        vm.expectRevert(BridgeVault.NotFreezer.selector);
        vault.setFrozen(true, true);
        vm.prank(admin);
        vm.expectRevert(BridgeVault.NotFreezer.selector);
        vault.setTokenFrozen(ETH, true, true);
    }

    function test_Sec2_repeatedCommitmentReverts() public {
        _deposit(ETH, D_ETH, "c");
        vm.prank(alice);
        vm.expectRevert(BridgeVault.CommitmentSeen.selector);
        vault.deposit{value: D_ETH}(ETH, D_ETH, "c");
        vm.prank(alice);
        vm.expectRevert(BridgeVault.CommitmentSeen.selector);
        vault.deposit(usdt, D_USD, "c"); // across tokens too
    }

    function test_F2_depositEventCarriesConfigId() public {
        vm.expectEmit(true, true, true, true, address(vault));
        emit Deposit("c", usdt, CFG, D_USD);
        _deposit(usdt, D_USD, "c");
        assertEq(vault.CONFIG_ID(), CFG);
    }

    function test_F10_onlyAdminConfigures() public {
        vm.expectRevert();
        vault.setDenom(ETH, 1 ether, true, 0);
        vm.prank(freezer);
        vm.expectRevert();
        vault.setMinLezDepth(5);
    }

    function test_F13_standardFeeBoundedByMaxFee() public {
        vm.prank(admin);
        vm.expectRevert(BridgeVault.BadParam.selector);
        vault.setDenom(ETH, 1 ether, true, uint128(0.05 ether + 1));
        vm.prank(admin);
        vault.setDenom(ETH, 1 ether, true, uint128(0.05 ether));
    }
}

contract CapsTest is BridgeBase {
    function test_F11_depositCapFixedWindow() public {
        for (uint256 i = 0; i < 4; i++) {
            _deposit(ETH, D_ETH, bytes32(i + 1));
        }
        vm.prank(alice);
        vm.expectRevert(BridgeVault.CapExceeded.selector);
        vault.deposit{value: D_ETH}(ETH, D_ETH, "x");
        _deposit(usdt, D_USD, "per-token cap");

        vm.warp(T0 + W - 1); // still the same window
        vm.prank(alice);
        vm.expectRevert(BridgeVault.CapExceeded.selector);
        vault.deposit{value: D_ETH}(ETH, D_ETH, "x");

        vm.warp(T0 + W); // exactly on the boundary: new window
        _deposit(ETH, D_ETH, "x");
        assertEq(vault.depositUsed(ETH, T0 / W), 4 * D_ETH);
        assertEq(vault.depositUsed(ETH, T0 / W + 1), D_ETH);
    }

    function test_F11_releaseCapFixedWindowAndBoundary() public {
        _fund(ETH, D_ETH, 4);
        _accept(ETH, D_ETH, "r");
        vm.warp(T0 + W - 1); // matured, last second of the window
        _release(ETH, D_ETH, "r", "n1", alice, 0);
        _release(ETH, D_ETH, "r", "n2", alice, 0);
        bytes memory s = _seal(ETH, D_ETH, "r", "n3", alice, 0);
        vm.expectRevert(BridgeVault.CapExceeded.selector);
        vault.release(ETH, D_ETH, "r", "n3", alice, relayer, 0, s);

        vm.warp(T0 + W); // boundary belongs to the new window
        vault.release(ETH, D_ETH, "r", "n3", alice, relayer, 0, s);
        assertEq(vault.releaseUsed(ETH, T0 / W + 1), D_ETH);
    }

    function test_Sec4_burstFullCapInFirstBlockAfterDelay() public {
        _fund(ETH, D_ETH, 4);
        _accept(ETH, D_ETH, "r");
        vm.warp(T0 + D);
        _release(ETH, D_ETH, "r", "n1", alice, 0);
        _release(ETH, D_ETH, "r", "n2", alice, 0);
        assertEq(vault.releaseUsed(ETH, T0 / W), 2 * D_ETH);
    }
}
