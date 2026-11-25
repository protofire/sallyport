# RFP-022 Ethereum vault (Foundry)

`BridgeVault` (escrow, one per config), `IBurnRootVerifier`, and `EcdsaRootVerifier`: interim, custodial, not trustless (2-of-2 secp256k1 root signers; `TRUSTLESS() == false`). Design: [../../docs/ARCHITECTURE.md](../../docs/ARCHITECTURE.md) (RFP-022 section); trust model: [../../docs/TRUST-ASSUMPTIONS.md](../../docs/TRUST-ASSUMPTIONS.md).

Pins: OpenZeppelin v5.7.0, risc0-ethereum v3.1.0 and forge-std v1.11.0, all git submodules in `lib/` at the revisions recorded in `foundry.lock`; Foundry 1.5.1. `test/mocks/TetherToken.sol` is the verified mainnet USDT source (Sourcify full match), compiled with its mainnet compiler solc 0.4.18.

```sh
git submodule update --init --recursive contracts/bridge/lib   # from the repository root
cd contracts/bridge && forge test -vv
```

`test/Vectors.t.sol` reads `fixtures/b22/vectors.json` and checks the Deposit / BurnRoot* topic0s, the root digest, the 352-byte release journal and its sha256, then runs deposit, accept, release on the vector values. `test/RealSeal.t.sol` verifies the real Groth16 seal in `test/fixtures/real_seal.json` against the Sepolia verifier; it is skipped unless `SEPOLIA_RPC` is set.

## Root signers

Signers sign the raw root digest (`EcdsaRootVerifier.rootDigest`, no EIP-191 prefix); the attestation is the two 65-byte `(r, s, v)` signatures ordered by ascending signer address. The signers of the live Sepolia deployment are listed in [deployments/sepolia.json](deployments/sepolia.json); signer 2's key exists only on signer host 2.

## Sepolia deploy

Order: `predict` the vault address, compute `cfg` with the predicted vault and the LEZ `bridge_program_id`, then deploy.

```sh
forge script script/Deploy.s.sol --sig "predict(address)" <deployer> --rpc-url $SEPOLIA_RPC
CONFIG_ID=0x… SIGNER_1=0x… SIGNER_2=0x… MEMBERSHIP_IMAGE_ID=0x… EXPECTED_VAULT=0x… FREEZER=0x… \
  forge script script/Deploy.s.sol --rpc-url $SEPOLIA_RPC --broadcast --private-key $SEPOLIA_KEY
```

The script deploys the USDT mock (unless `USDT` is set), the verifier and the vault, asserts the vault address, and registers ETH (`d = 0.01 ETH`) and USDT-mock (`d = 100e6`): delay 600 s, 24 h windows, deposit cap `4·d`, release cap `2·d`, standard fee 1%, `minLezDepth = 10`, `MAX_FEE_BPS = 500`, Groth16 verifier `0x2a098988600d87650Fb061FfAff08B97149Fa84D` (never the router).

Gas on Sepolia: the node prices contract creation far above Foundry's local EVM (`forge script` estimated 633k for the verifier, the node needs about 4.07M, and a first deployment burned two nonces on out-of-gas creations). `script/deploy_sepolia.py` therefore takes every gas limit from the node's `eth_estimateGas` (times 1.2) and refuses to send if the deployer nonce no longer gives the expected vault address. The live deployment and its transactions are in [deployments/sepolia.json](deployments/sepolia.json) and [../../evidence/rfp022-sepolia.md](../../evidence/rfp022-sepolia.md).
