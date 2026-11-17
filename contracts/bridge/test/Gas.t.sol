// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {BridgeBase} from "./Base.t.sol";

/// P3 gas (execution gas of the call, excl. the 21k base and calldata). Release uses the risc0 mock
/// verifier; the real RiscZeroGroth16Verifier adds ~250k per verify (DECISIONS.md B22-5).
contract GasTest is BridgeBase {
    /// Each measured call as in its own transaction: contracts and slots cold.
    function _cool() internal {
        vm.cool(address(vault));
        vm.cool(address(verifier));
        vm.cool(address(groth));
        vm.cool(usdt);
    }

    function test_P3_gas() public {
        uint256 g;
        _cool();
        g = gasleft();
        _deposit(ETH, D_ETH, "c1");
        emit log_named_uint("deposit ETH (first)", g - gasleft());
        _cool();
        g = gasleft();
        _deposit(ETH, D_ETH, "c2");
        emit log_named_uint("deposit ETH (window already used)", g - gasleft());
        _cool();
        g = gasleft();
        _deposit(usdt, D_USD, "c3");
        emit log_named_uint("deposit USDT mock (first)", g - gasleft());

        bytes memory att = _att(_digest(usdt, D_USD, "r", 1));
        _cool();
        g = gasleft();
        vault.acceptBurnRoot(usdt, D_USD, "r", 1, 100, bytes32(uint256(0xb10c)), att);
        emit log_named_uint("acceptBurnRoot 2-of-2", g - gasleft());
        _accept(ETH, D_ETH, "r");

        vm.warp(T0 + D);
        address to = makeAddr("recipient_j");
        bytes memory s = _seal(usdt, D_USD, "r", "n1", to, D_USD / 100);
        _cool();
        g = gasleft();
        vault.release(usdt, D_USD, "r", "n1", to, relayer, D_USD / 100, s);
        emit log_named_uint("release USDT mock (mock seal)", g - gasleft());
        s = _seal(ETH, D_ETH, "r", "n2", to, D_ETH / 100);
        _cool();
        g = gasleft();
        vault.release(ETH, D_ETH, "r", "n2", to, relayer, D_ETH / 100, s);
        emit log_named_uint("release ETH (mock seal)", g - gasleft());
    }
}
