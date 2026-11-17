// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {BridgeBase} from "./Base.t.sol";
import {BridgeVault} from "../src/BridgeVault.sol";
import {EcdsaRootVerifier} from "../src/EcdsaRootVerifier.sol";

contract RootAcceptanceTest is BridgeBase {
    event BurnRootAccepted(
        address indexed token,
        uint256 indexed denom,
        bytes32 indexed burnRoot,
        uint64 count,
        uint64 lezHeight,
        bytes32 lezBlockHash
    );

    bytes32 constant ROOT = "root";
    bytes32 constant BH = bytes32(uint256(0xb10c));

    function _submit(bytes memory att) internal {
        vault.acceptBurnRoot(usdt, D_USD, ROOT, 1, 100, BH, att);
    }

    function test_F7_twoOfTwoAcceptedWithEvent() public {
        vm.expectEmit(true, true, true, true, address(vault));
        emit BurnRootAccepted(usdt, D_USD, ROOT, 1, 100, BH);
        _submit(_att(_digest(usdt, D_USD, ROOT, 1)));
        assertEq(vault.acceptedAt(usdt, D_USD, ROOT), T0);
    }

    function test_F7_interimLabel() public view {
        assertFalse(verifier.TRUSTLESS());
        assertEq(verifier.THRESHOLD(), 2);
        assertEq(verifier.CONFIG_ID(), CFG);
        assertEq(verifier.signers().length, 2);
    }

    function test_Sec2_oneSignatureReverts() public {
        bytes32 h = _digest(usdt, D_USD, ROOT, 1);
        vm.expectRevert(abi.encodeWithSelector(EcdsaRootVerifier.BadAttestationLength.selector, 65));
        _submit(_sig(pkLo, h));
        bytes memory three = bytes.concat(_att(h), _sig(pkHi, h));
        vm.expectRevert(abi.encodeWithSelector(EcdsaRootVerifier.BadAttestationLength.selector, 195));
        _submit(three);
    }

    function test_Sec2_duplicatedSignatureReverts() public {
        bytes32 h = _digest(usdt, D_USD, ROOT, 1);
        vm.expectRevert(EcdsaRootVerifier.SignersNotAscending.selector);
        _submit(bytes.concat(_sig(pkLo, h), _sig(pkLo, h)));
    }

    function test_Sec2_unsortedSignaturesRevert() public {
        bytes32 h = _digest(usdt, D_USD, ROOT, 1);
        vm.expectRevert(EcdsaRootVerifier.SignersNotAscending.selector);
        _submit(bytes.concat(_sig(pkHi, h), _sig(pkLo, h)));
    }

    function test_Sec2_nonSignerReverts() public {
        bytes32 h = _digest(usdt, D_USD, ROOT, 1);
        uint256 pkX = uint256(keccak256("not a signer"));
        vm.expectRevert(abi.encodeWithSelector(EcdsaRootVerifier.NotASigner.selector, vm.addr(pkX)));
        _submit(bytes.concat(_sig(pkLo, h), _sig(pkX, h)));
    }

    function test_Sec2_highSReverts() public {
        bytes32 h = _digest(usdt, D_USD, ROOT, 1);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pkHi, h);
        uint256 n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        bytes32 hs = bytes32(n - uint256(s));
        vm.expectRevert(abi.encodeWithSelector(ECDSA.ECDSAInvalidSignatureS.selector, hs));
        _submit(bytes.concat(_sig(pkLo, h), abi.encodePacked(r, hs, v == 27 ? uint8(28) : uint8(27))));
    }

    /// A valid 2-of-2 attestation over any other field must not authorise this root.
    function test_F15_signatureForOtherFieldsReverts() public {
        address v = address(vault);
        bytes32[8] memory wrong = [
            verifier.rootDigest(v, ETH, D_USD, ROOT, 1, 100, BH), // token
            verifier.rootDigest(v, usdt, D_USD + 1, ROOT, 1, 100, BH), // denom
            verifier.rootDigest(v, usdt, D_USD, ROOT, 2, 100, BH), // count
            verifier.rootDigest(v, usdt, D_USD, ROOT, 1, 101, BH), // lezHeight
            verifier.rootDigest(v, usdt, D_USD, ROOT, 1, 100, bytes32(uint256(1))), // lezBlockHash
            verifier.rootDigest(address(0xbeef), usdt, D_USD, ROOT, 1, 100, BH), // vault
            _otherConfigDigest(), // CONFIG_ID
            _otherChainDigest() // chain id
        ];
        for (uint256 i = 0; i < wrong.length; i++) {
            vm.expectPartialRevert(EcdsaRootVerifier.NotASigner.selector);
            _submit(_att(wrong[i]));
        }
        assertEq(vault.acceptedAt(usdt, D_USD, ROOT), 0);
    }

    function _otherConfigDigest() internal returns (bytes32) {
        address[] memory s = verifier.signers();
        EcdsaRootVerifier other = new EcdsaRootVerifier(s, 2, keccak256("look-alike cfg"));
        return other.rootDigest(address(vault), usdt, D_USD, ROOT, 1, 100, BH);
    }

    function _otherChainDigest() internal returns (bytes32 h) {
        uint256 id = block.chainid;
        vm.chainId(1);
        h = _digest(usdt, D_USD, ROOT, 1);
        vm.chainId(id);
    }

    function test_R3_resubmittedRootRevertsAndKeepsAcceptedAt() public {
        bytes memory att = _att(_digest(usdt, D_USD, ROOT, 1));
        _submit(att);
        vm.warp(T0 + 500);
        vm.expectRevert(BridgeVault.RootAlreadyAccepted.selector);
        _submit(att);
        assertEq(vault.acceptedAt(usdt, D_USD, ROOT), T0);
    }

    function test_F7_olderRootAcceptedAfterNewerIsUsable() public {
        _fund(usdt, D_USD, 2);
        vault.acceptBurnRoot(usdt, D_USD, "new", 5, 100, BH, _att(_digest(usdt, D_USD, "new", 5)));
        vault.acceptBurnRoot(usdt, D_USD, "old", 2, 100, BH, _att(_digest(usdt, D_USD, "old", 2)));
        vm.warp(T0 + D);
        _release(usdt, D_USD, "old", "nb", alice, 0);
        assertTrue(vault.spent("nb"));
    }

    function test_F16_rootForUsdtNotUsableForEth() public {
        _fund(ETH, D_ETH, 1);
        _accept(usdt, D_USD, ROOT);
        vm.warp(T0 + D);
        bytes memory s = _seal(ETH, D_ETH, ROOT, "nb", alice, 0);
        vm.expectRevert(BridgeVault.RootNotAccepted.selector);
        vault.release(ETH, D_ETH, ROOT, "nb", alice, relayer, 0, s);
    }

    function test_F12_raisingMinLezDepthKeepsAcceptedRoots() public {
        _fund(usdt, D_USD, 1);
        _accept(usdt, D_USD, ROOT);
        vm.prank(admin);
        vault.setMinLezDepth(1000);
        assertEq(vault.minLezDepth(), 1000);
        vm.warp(T0 + D);
        _release(usdt, D_USD, ROOT, "nb", alice, 0);
    }

    function test_Sec8_constructorRejectsBadSignerSets() public {
        address[] memory s = new address[](2);
        s[0] = address(1);
        s[1] = address(1);
        vm.expectRevert(abi.encodeWithSelector(EcdsaRootVerifier.BadSigner.selector, address(1)));
        new EcdsaRootVerifier(s, 2, CFG);
        s[1] = address(2);
        vm.expectRevert(EcdsaRootVerifier.BadThreshold.selector);
        new EcdsaRootVerifier(s, 3, CFG);
        vm.expectRevert(EcdsaRootVerifier.BadThreshold.selector);
        new EcdsaRootVerifier(s, 0, CFG);
    }
}
