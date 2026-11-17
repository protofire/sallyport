// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {RiscZeroMockVerifier} from "risc0/test/RiscZeroMockVerifier.sol";
import {BridgeVault} from "../src/BridgeVault.sol";
import {EcdsaRootVerifier} from "../src/EcdsaRootVerifier.sol";
import {FeeOnTransferToken} from "./mocks/FeeOnTransferToken.sol";

/// The verified mainnet USDT ABI: `transfer`/`transferFrom`/`approve` return nothing.
interface IUSDT {
    function transfer(address to, uint256 value) external;
    function approve(address spender, uint256 value) external;
    function setParams(uint256 newBasisPoints, uint256 newMaxFee) external;
    function balanceOf(address who) external view returns (uint256);
}

abstract contract BridgeBase is Test {
    bytes32 constant CFG = keccak256("test cfg");
    bytes32 constant IMAGE = keccak256("burn_member image");
    uint256 constant W = 1 days;
    uint64 constant D = 600;
    uint256 constant MIN_TL = 600; // vault MIN_TIMELOCK
    uint256 constant T0 = 1000 * W; // window-aligned start
    address constant ETH = address(0);
    uint256 constant D_ETH = 0.01 ether;
    uint256 constant D_USD = 100e6;

    address admin = makeAddr("admin");
    address freezer = makeAddr("freezer");
    address alice = makeAddr("alice");
    address relayer = makeAddr("relayer");

    uint256 pkA = uint256(keccak256("signer A"));
    uint256 pkB = uint256(keccak256("signer B"));
    uint256 pkLo; // signer with the lower address
    uint256 pkHi;

    RiscZeroMockVerifier groth;
    EcdsaRootVerifier verifier;
    BridgeVault vault;
    address usdt;
    FeeOnTransferToken tok6;
    FeeOnTransferToken tok18;
    FeeOnTransferToken fot;

    function setUp() public virtual {
        vm.warp(T0);
        (pkLo, pkHi) = vm.addr(pkA) < vm.addr(pkB) ? (pkA, pkB) : (pkB, pkA);
        address[] memory s = new address[](2);
        s[0] = vm.addr(pkLo);
        s[1] = vm.addr(pkHi);
        groth = new RiscZeroMockVerifier(bytes4(0xb22b22b2));
        verifier = new EcdsaRootVerifier(s, 2, CFG);
        vault = new BridgeVault(admin, freezer, verifier, groth, IMAGE, CFG, 500, MIN_TL);

        usdt = deployCode(
            "out/TetherToken.sol/TetherToken.json", abi.encode(uint256(1e15), "Tether USD", "USDT", uint256(6))
        );
        tok6 = new FeeOnTransferToken(6, 0);
        tok18 = new FeeOnTransferToken(18, 0);
        fot = new FeeOnTransferToken(18, 100);

        _list(ETH, D_ETH);
        _list(usdt, D_USD);
        _list(address(tok6), 100e6);
        _list(address(tok18), 1e18);
        _list(address(fot), 1e18);

        vm.deal(alice, 100 ether);
        IUSDT(usdt).transfer(alice, 1e12);
        tok6.mint(alice, 1e12);
        tok18.mint(alice, 1e24);
        fot.mint(alice, 1e24);
        vm.startPrank(alice);
        IUSDT(usdt).approve(address(vault), type(uint256).max);
        tok6.approve(address(vault), type(uint256).max);
        tok18.approve(address(vault), type(uint256).max);
        fot.approve(address(vault), type(uint256).max);
        vm.stopPrank();
    }

    /// Demo parameters (see contracts/bridge/README.md): delay D, window W, deposit cap 4·d, release cap 2·d, standard fee 1%.
    function _list(address token, uint256 d) internal {
        vm.startPrank(admin);
        vault.setToken(
            token,
            BridgeVault.TokenConfig({
                listed: true,
                depositsOpen: true,
                releaseDelay: D,
                window: uint64(W),
                depositCap: uint128(4 * d),
                releaseCap: uint128(2 * d)
            })
        );
        vault.setDenom(token, d, true, uint128(d / 100));
        vm.stopPrank();
    }

    function _deposit(address token, uint256 d, bytes32 c) internal {
        vm.prank(alice);
        vault.deposit{value: token == ETH ? d : 0}(token, d, c);
    }

    function _sig(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _digest(address token, uint256 d, bytes32 root, uint64 count) internal view returns (bytes32) {
        return verifier.rootDigest(address(vault), token, d, root, count, 100, bytes32(uint256(0xb10c)));
    }

    function _att(bytes32 digest) internal view returns (bytes memory) {
        return bytes.concat(_sig(pkLo, digest), _sig(pkHi, digest));
    }

    function _accept(address token, uint256 d, bytes32 root) internal {
        vault.acceptBurnRoot(token, d, root, 1, 100, bytes32(uint256(0xb10c)), _att(_digest(token, d, root, 1)));
    }

    function _seal(address token, uint256 d, bytes32 root, bytes32 nb, address to, uint256 fee)
        internal
        view
        returns (bytes memory)
    {
        bytes memory j = vault.releaseJournal(token, d, root, nb, to, relayer, fee);
        return groth.mockProve(IMAGE, sha256(j)).seal;
    }

    function _release(address token, uint256 d, bytes32 root, bytes32 nb, address to, uint256 fee) internal {
        vault.release(token, d, root, nb, to, relayer, fee, _seal(token, d, root, nb, to, fee));
    }

    /// Fill escrow with `n` deposits of (token, d), spread over windows to stay under the deposit cap.
    function _fund(address token, uint256 d, uint256 n) internal {
        uint256 t = block.timestamp;
        for (uint256 i = 0; i < n; i++) {
            if (i % 4 == 0 && i != 0) vm.warp(block.timestamp + W);
            _deposit(token, d, keccak256(abi.encode("fund", token, d, i)));
        }
        vm.warp(t);
    }
}
