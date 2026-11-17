// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// ERC-20 that burns `feeBps` of every transfer. With `feeBps == 0` it is a plain ERC-20 of any decimals.
contract FeeOnTransferToken is ERC20 {
    uint8 private immutable _dec;
    uint256 public immutable feeBps;

    constructor(uint8 dec, uint256 feeBps_) ERC20("Mock", "MOCK") {
        _dec = dec;
        feeBps = feeBps_;
    }

    function decimals() public view override returns (uint8) {
        return _dec;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function _update(address from, address to, uint256 value) internal override {
        if (from != address(0) && to != address(0) && feeBps != 0) {
            uint256 fee = value * feeBps / 10_000;
            super._update(from, address(0), fee);
            value -= fee;
        }
        super._update(from, to, value);
    }
}
