"""RFP-022 Sepolia deploy, same order and parameters as Deploy.s.sol, with every gas limit taken from the node.

forge's script simulation underestimates contract creation on Sepolia (~7x; two creations ran out of gas in the
2026-11-09 deploy, evidence/rfp022-sepolia.md), so each tx here is estimated with eth_estimateGas against the node right
before it is sent (+20%), with explicit nonces N (USDT mock), N+1 (EcdsaRootVerifier), N+2 (BridgeVault), then the
demo registration. Refuses to send anything if the deployer nonce no longer gives EXPECTED_VAULT.

  forge build   # in contracts/bridge
  SEPOLIA_KEY=… CONFIG_ID=… SIGNER_1=… SIGNER_2=… MEMBERSHIP_IMAGE_ID=… EXPECTED_VAULT=… FREEZER=… \
    python3 -I script/deploy_sepolia.py > deploy.json
Key: env SEPOLIA_KEY only, never printed. RPC: env SEPOLIA_RPC.
"""
import json, os, sys, time
from pathlib import Path
from eth_abi import encode
from eth_account import Account
from eth_utils import keccak, to_checksum_address as checksum

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))
from sepolia import rpc, receipt  # noqa: E402  (contracts/sepolia.py: retrying JSON-RPC)

GROTH16_V3 = "0x2a098988600d87650Fb061FfAff08B97149Fa84D"
MAX_FEE_BPS, RELEASE_DELAY, WINDOW, MIN_LEZ_DEPTH = 500, 600, 86400, 10
D_ETH, D_USDT = 10**16, 100 * 10**6


def artifact(path):
    return bytes.fromhex(json.loads((HERE.parent / "out" / path).read_text())["bytecode"]["object"][2:])


def create_address(sender, nonce):
    import rlp  # dependency of eth_account
    return checksum(keccak(rlp.encode([bytes.fromhex(sender[2:]), nonce]))[12:])


def call_data(sig, types, args):
    return keccak(text=sig)[:4] + encode(types, args)


def main():
    acct = Account.from_key(os.environ["SEPOLIA_KEY"])
    env = os.environ
    cfg, image = bytes.fromhex(env["CONFIG_ID"][2:]), bytes.fromhex(env["MEMBERSHIP_IMAGE_ID"][2:])
    signers = sorted([checksum(env["SIGNER_1"]), checksum(env["SIGNER_2"])], key=lambda a: int(a, 16))
    freezer = checksum(env["FREEZER"])
    min_timelock = int(env.get("MIN_TIMELOCK", 6 * 3600))  # as Deploy.s.sol: bounds 10 min..30 days
    if freezer == acct.address:
        sys.exit("FREEZER must not be the deployer (admin)")
    n = int(rpc("eth_getTransactionCount", acct.address, "pending"), 16)
    usdt, verifier, vault = (create_address(acct.address, n + i) for i in range(3))
    if vault != checksum(env["EXPECTED_VAULT"]):
        sys.exit(f"vault would land at {vault}, not EXPECTED_VAULT (nonce {n})")
    txs = [
        ("TetherToken mock", None, artifact("TetherToken.sol/TetherToken.json")
         + encode(["uint256", "string", "string", "uint256"], [10**12, "Tether USD (b22 mock)", "USDT", 6])),
        ("EcdsaRootVerifier", None, artifact("EcdsaRootVerifier.sol/EcdsaRootVerifier.json")
         + encode(["address[]", "uint256", "bytes32"], [signers, 2, cfg])),
        ("BridgeVault", None, artifact("BridgeVault.sol/BridgeVault.json")
         + encode(["address", "address", "address", "address", "bytes32", "bytes32", "uint256", "uint256"],
                  [acct.address, freezer, verifier, GROTH16_V3, image, cfg, MAX_FEE_BPS, min_timelock])),
    ]
    tc = "setToken(address,(bool,bool,uint64,uint64,uint128,uint128))"
    for name, tok, d in [("ETH", "0x" + "00" * 20, D_ETH), ("USDT", usdt, D_USDT)]:
        txs.append((f"setToken {name}", vault, call_data(tc, ["address", "(bool,bool,uint64,uint64,uint128,uint128)"],
                                                         [tok, (True, True, RELEASE_DELAY, WINDOW, 4 * d, 2 * d)])))
        txs.append((f"setDenom {name}", vault, call_data("setDenom(address,uint256,bool,uint128)",
                                                         ["address", "uint256", "bool", "uint128"], [tok, d, True, d // 100])))
    txs.append(("setMinLezDepth", vault, call_data("setMinLezDepth(uint64)", ["uint64"], [MIN_LEZ_DEPTH])))

    out = {"deployer": acct.address, "nonce": n, "usdt": usdt, "verifier": verifier, "vault": vault,
           "constructor": {"verifier": {"signers": signers, "threshold": 2, "config_id": env["CONFIG_ID"]},
                           "vault": {"admin": acct.address, "freezer": freezer, "root_verifier": verifier,
                                     "groth16": GROTH16_V3, "membership_image_id": env["MEMBERSHIP_IMAGE_ID"],
                                     "config_id": env["CONFIG_ID"], "max_fee_bps": MAX_FEE_BPS,
                                     "min_timelock": min_timelock}},
           "txs": []}
    for i, (name, to, data) in enumerate(txs):
        call = {"from": acct.address, "data": "0x" + data.hex(), **({"to": to} if to else {})}
        est = int(rpc("eth_estimateGas", call), 16)  # the node's estimate, never forge's
        base = int(rpc("eth_getBlockByNumber", "latest", False)["baseFeePerGas"], 16)
        tip = max(int(rpc("eth_maxPriorityFeePerGas"), 16), 10**6)
        tx = {"chainId": 11155111, "type": 2, "nonce": n + i, "maxPriorityFeePerGas": tip,
              "maxFeePerGas": 2 * base + tip, "gas": est * 6 // 5, "to": to and checksum(to), "value": 0,
              "data": data}
        h = rpc("eth_sendRawTransaction", "0x" + acct.sign_transaction(tx).raw_transaction.hex())
        r = receipt(h)
        row = {"name": name, "nonce": n + i, "tx": h, "block": int(r["blockNumber"], 16), "gas_limit": tx["gas"],
               "node_estimate": est, "gas_used": int(r["gasUsed"], 16), "status": r["status"],
               "contract": r.get("contractAddress")}
        print(json.dumps(row), file=sys.stderr, flush=True)
        out["txs"].append(row)
        if r["status"] != "0x1":
            sys.exit(f"{name} failed: {h}")
    assert out["txs"][2]["contract"].lower() == vault.lower(), "vault landed elsewhere"
    rv = rpc("eth_call", {"to": vault, "data": "0x" + keccak(text="ROOT_VERIFIER()")[:4].hex()}, "latest")
    out["ROOT_VERIFIER()"] = checksum("0x" + rv[-40:])
    assert out["ROOT_VERIFIER()"] == verifier, "ROOT_VERIFIER() readback differs"
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
