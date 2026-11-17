"""Deploy DepositVault to Sepolia and make deposits (testnet only).

Key: env SEPOLIA_KEY (hex), never printed or written. RPC: env SEPOLIA_RPC.
  python3 -I sepolia.py deploy                         -> deploys contracts/DepositVault.bin, checks runtime code
  python3 -I sepolia.py deposit <vault> <wei> <nk_out> -> one deposit with a fresh nk, now; appends nk + tx to nk_out
Any block is claimable: the claim walks the parent-hash chain from the deposit block to a later recorded
header (ancestry, up to 448 headers), so deposits no longer aim at the last slot of an epoch.
Commitment = sha256("rfp021/commit" || nk) (consumers::commit).
"""
import hashlib, json, os, secrets, sys, time, urllib.request
from pathlib import Path
from eth_account import Account
from eth_utils import to_checksum_address as checksum

RPC = os.environ.get("SEPOLIA_RPC", "https://0xrpc.io/sep")
GENESIS = 1655733600  # Sepolia beacon genesis time
HERE = Path(__file__).resolve().parent


def rpc(method, *params, tries=10):
    for i in range(tries):
        try:
            return _rpc(method, *params)
        except Exception as e:  # rate limits / transient network errors
            if i == tries - 1:
                raise
            print(f"retry {method}: {e}", file=sys.stderr)
            time.sleep(3 * (i + 1))


def _rpc(method, *params):
    req = urllib.request.Request(RPC, json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": list(params)}).encode(),
                                 {"Content-Type": "application/json", "User-Agent": "rfp021-deposit/1"})
    r = json.load(urllib.request.urlopen(req, timeout=30))
    if "error" in r:
        raise RuntimeError(f"{method}: {r['error']}")
    return r["result"]


def send(acct, to, data, value):
    call = {"from": acct.address, "data": data, "value": hex(value), **({"to": to} if to else {})}
    gas = int(rpc("eth_estimateGas", call), 16) * 6 // 5  # Sepolia gas schedule changes; never hard-code
    base = int(rpc("eth_getBlockByNumber", "latest", False)["baseFeePerGas"], 16)
    tip = max(int(rpc("eth_maxPriorityFeePerGas"), 16), 2 * 10**9)
    tx = {"chainId": 11155111, "type": 2, "nonce": int(rpc("eth_getTransactionCount", acct.address, "pending"), 16),
          "maxPriorityFeePerGas": tip, "maxFeePerGas": 2 * base + tip, "gas": gas, "to": to and checksum(to), "value": value, "data": data}
    signed = acct.sign_transaction(tx)
    return rpc("eth_sendRawTransaction", "0x" + signed.raw_transaction.hex())


def receipt(h):
    while (r := rpc("eth_getTransactionReceipt", h)) is None:
        time.sleep(3)
    return r


def slot_of(block_number):
    return (int(rpc("eth_getBlockByNumber", block_number, False)["timestamp"], 16) - GENESIS) // 12


def main():
    acct = Account.from_key(os.environ["SEPOLIA_KEY"])
    cmd = sys.argv[1]
    if cmd == "deploy":
        code = "0x" + (HERE / "DepositVault.bin").read_text().strip()
        h = send(acct, None, code, 0)
        r = receipt(h)
        assert r["status"] == "0x1", r
        addr = r["contractAddress"]
        onchain = rpc("eth_getCode", addr, "latest")[2:]
        expected = (HERE / "DepositVault.bin-runtime").read_text().strip()
        cost = int(r["gasUsed"], 16) * int(r["effectiveGasPrice"], 16)
        print(f"deployed {addr} tx {h} block {int(r['blockNumber'], 16)} runtime_code_matches={onchain == expected} cost_wei={cost}")
    elif cmd == "deposit":
        vault, wei, out = sys.argv[2], int(sys.argv[3]), Path(sys.argv[4])
        nk = secrets.token_bytes(32)
        c = hashlib.sha256(b"rfp021/commit" + nk).digest()
        with out.open("a") as f:  # persist the secret before the deposit exists
            f.write(json.dumps({"nk": nk.hex(), "commitment": c.hex(), "status": "pre-send"}) + "\n")
        h = send(acct, vault, "0xb214faa5" + c.hex(), wei)
        r = receipt(h)
        slot = slot_of(r["blockNumber"])
        cost = int(r["gasUsed"], 16) * int(r["effectiveGasPrice"], 16) + wei
        with out.open("a") as f:
            f.write(json.dumps({"nk": nk.hex(), "commitment": c.hex(), "tx": h, "block": int(r["blockNumber"], 16),
                                "block_hash": r["blockHash"], "slot": slot, "status": r["status"]}) + "\n")
        print(f"deposit tx {h} block {int(r['blockNumber'], 16)} slot {slot} (slot%32={slot % 32}) "
              f"status {r['status']} cost_wei={cost} commitment=0x{c.hex()}", flush=True)
        assert r["status"] == "0x1", "deposit reverted"
    elif cmd == "erc20":  # real ERC-20 deposit: wrap ETH into Sepolia WETH9, then transfer(to, wei) -> Transfer log
        to, wei = sys.argv[2], int(sys.argv[3])
        r = receipt(send(acct, WETH, "0xd0e30db0", wei))  # deposit()
        assert r["status"] == "0x1", "wrap reverted"
        h = send(acct, WETH, "0xa9059cbb" + to.lower()[2:].rjust(64, "0") + hex(wei)[2:].rjust(64, "0"), 0)
        r = receipt(h)
        assert r["status"] == "0x1", "transfer reverted"
        log = next(l for l in r["logs"] if l["address"].lower() == WETH.lower() and l["topics"][0] == TRANSFER)
        print(f"erc20 transfer tx {h} block {int(r['blockNumber'], 16)} block_hash {r['blockHash']} "
              f"tx_index {int(r['transactionIndex'], 16)} log_index_in_tx {r['logs'].index(log)} token {WETH} to {to} wei {wei}", flush=True)

WETH = "0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14"  # Sepolia WETH9
TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

if __name__ == "__main__":
    main()
