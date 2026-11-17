// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.15;

/// RFP-021 F8 reference deposit contract (docs/PRIVACY-DESIGN.md section 3.3). No admin, no
/// withdrawal: deposited ETH stays here (withdrawal is RFP-022 scope). The depositor picks a
/// secret `nk` and passes `commitment = sha256("rfp021/commit" || nk)`; the private consumer
/// proves this log and checks topic1 == commitment and data word 0 == its fixed denomination.
contract DepositVault {
    event Deposit(bytes32 indexed commitment, uint256 amount);

    function deposit(bytes32 commitment) external payable {
        emit Deposit(commitment, msg.value);
    }
}
