#!/usr/bin/env python3
"""Generate / check the SPEL-format IDLs for the attest program and the reference consumers.

Types, variant names, field names/order and error codes are PARSED from the Rust source, so the
committed IDL cannot drift: `gen_idl.py --check` (run by CI) regenerates and diffs it, and also
verifies the hand-written parts (PDA seed tags/params, event selector, seed paths) against source.

    python3 idl/gen_idl.py           # rewrite idl/*.idl.json
    python3 idl/gen_idl.py --check   # exit 1 on any drift
Only the Python 3 stdlib is used.
"""
import hashlib, json, re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = {
    "lc": ROOT / "crates/lc-core/src/lib.rs",
    "sync": ROOT / "crates/lc-core/src/sync.rs",
    "inc": ROOT / "crates/inclusion/src/lib.rs",
    "att": ROOT / "crates/attest-program/src/lib.rs",
    "con": ROOT / "crates/consumers/src/lib.rs",
}
PRIM = {"u8", "u16", "u32", "u64", "u128", "i8", "i16", "i32", "i64", "i128", "bool", "String"}


def read(p):
    return re.sub(r"//[^\n]*", "", p.read_text())


TEXT = {k: read(v) for k, v in SRC.items()}
ALL = "\n".join(TEXT.values())


def split_top(s):
    out, d, cur = [], 0, ""
    for ch in s:
        d += ch in "<([{"
        d -= ch in ">)]}"
        if ch == "," and d == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def strip_attrs(s):
    return re.sub(r"#\[[^\]]*\]", "", s).strip()


ALIASES = dict(re.findall(r"^pub type (\w+) = (.+);$", ALL, re.M))
CONSTS = dict(re.findall(r"^pub const (\w+): usize = ([^;]+);$", ALL, re.M))
CONSTS["HEADER_TREE_DEPTH"] = re.search(r"pub const HEADER_TREE_DEPTH: usize = (\d+)", ALL).group(1)

ITEMS = {}  # name -> ("struct"|"enum", body)
for kind, name, body in re.findall(r"^pub (struct|enum) (\w+) \{(.*?)^\}", ALL, re.S | re.M):
    ITEMS[name] = (kind, body)


def tname(t):
    if isinstance(t, str):
        return t
    k = next(iter(t))
    if k == "array":
        return f"{tname(t['array'][0])}x{t['array'][1]}"
    if k == "vec":
        return "vec_" + tname(t["vec"])
    if k == "option":
        return "opt_" + tname(t["option"])
    return t["defined"]


class Conv:
    def __init__(self):
        self.types = {}  # name -> typedef

    def ty(self, r):
        r = r.replace(" ", "")
        if r.startswith("Box<"):
            return self.ty(r[4:-1])
        if r.startswith("Vec<"):
            return {"vec": self.ty(r[4:-1])}
        if r.startswith("Option<"):
            return {"option": self.ty(r[7:-1])}
        if r.startswith("["):
            inner, n = r[1:-1].rsplit(";", 1)
            return {"array": [self.ty(inner), int(CONSTS.get(n, n))]}
        if r.startswith("("):
            parts = [self.ty(p) for p in split_top(r[1:-1])]
            name = "Tuple_" + "_".join(tname(p) for p in parts)
            self.types[name] = {"name": name, "kind": "struct", "fields": [{"name": str(i), "type": p} for i, p in enumerate(parts)]}
            return {"defined": name}
        if r in PRIM:
            return r
        if r in ALIASES:
            return self.ty(ALIASES[r])
        if r in ITEMS:
            self.define(r)
            return {"defined": r}
        raise SystemExit(f"unknown type {r!r}")

    def fields(self, body):
        out = []
        for f in split_top(strip_attrs(body)):
            n, t = strip_attrs(f).removeprefix("pub ").split(":", 1)
            out.append({"name": n.strip(), "type": self.ty(t.strip())})
        return out

    def variants(self, body):
        out = []
        for v in split_top(strip_attrs(body)):
            v = strip_attrs(v)
            m = re.fullmatch(r"(\w+)\s*(\{(.*)\}|\((.*)\))?", v, re.S)
            name, _, sf, tf = m.groups()
            if sf is not None:
                fs = self.fields(sf)
            elif tf is not None:
                fs = [{"name": str(i), "type": self.ty(t)} for i, t in enumerate(split_top(tf))]
            else:
                fs = []
            out.append({"name": name, "fields": fs})
        return out

    def define(self, name):
        if name in self.types:
            return
        self.types[name] = None  # break recursion
        kind, body = ITEMS[name]
        if kind == "struct":
            self.types[name] = {"name": name, "kind": "struct", "fields": self.fields(body)}
        else:
            self.types[name] = {"name": name, "kind": "enum", "variants": self.variants(body)}


def seed_fn(fn):
    m = re.search(rf"pub fn {fn}\(([^)]*)\)[^{{]*\{{(.*?)^\}}", ALL, re.S | re.M)
    if not m:
        raise SystemExit(f"seed fn {fn} not found")
    params = [p.split(":")[0].strip() for p in split_top(m.group(1))]
    tag = re.search(r'b"(rfp021/[^"]+)"', m.group(2)).group(1)
    return tag, params


def error_codes():
    body = re.search(r"pub enum ErrorCode \{(.*?)\}", TEXT["lc"], re.S).group(1)
    codes = {n: int(c) for n, c in re.findall(r"(\w+) = (\d+)", body)}
    inc = re.search(r"pub enum ErrorCode \{(.*?)\}", TEXT["inc"], re.S).group(1)
    for n, c in re.findall(r"(\w+) = (\d+)", inc):  # inclusion's subset must agree with lc-core
        assert codes[n] == int(c), f"inclusion ErrorCode {n} differs from lc-core"
    codes["AlreadyClaimed"] = int(re.search(r"ERR_ALREADY_CLAIMED: u16 = (\d+)", TEXT["con"]).group(1))
    return codes


ERR_MSG = {
    "Malformed": "Undecodable message, wrong receiver PDA, wrong/absent sender, or inconsistent input (incl. ancestry longer than MAX_ANCESTRY)",
    "ChainMismatch": "Chain binding differs from the instance",
    "ForkUnsupported": "Fork before Electra",
    "HeaderNotFinalised": "Header/instance/root unknown (finality branch fails or no such PDA state)",
    "SyncSigInvalid": "Sync aggregate pairing check failed",
    "ParticipationBelowThreshold": "Fewer than min_participation sync-committee signers",
    "HandoffNotVerified": "next_sync_committee branch fails or period gap",
    "CheckpointStale": "Outside the weak-subjectivity period",
    "UpdateNotNewer": "Duplicate / already applied / older update, job id in use, or instance already initialised",
    "BootstrapMismatch": "Bootstrap does not match the trusted block root",
    "ExecutionHeaderMismatch": "keccak(exec_header_rlp) != execution_block_hash, or a broken ancestry link (keccak(H_i) != parentHash(H_i+1))",
    "InclusionInvalid": "Merkle-Patricia proof invalid",
    "PredicateFailed": "A predicate does not hold on the proven fact",
    "StatementMismatch": "Reply/statement does not match the pinned instance, chain or predicates",
    "AlreadyClaimed": "Consumer-local: nullifier already spent (replay)",
}

# Seed functions: IDL key -> (rust fn, which program's id the PDA is derived under)
SEEDS = {
    "attest": {"instance": "instance_seed", "header": "header_seed", "job": "job_seed", "hroot": "hroot_seed"},
    "consumers": {"vault": "vault_seed", "nullifier": "nullifier_seed"},
}

ATTEST_PDA = {  # account name -> (seed key, {seed param: arg path | (arg path, transform)})
    "instance": ("instance", {"instance_id": "instance_id"}),
    "job": ("job", {"instance_id": "instance_id", "job_id": "job_id"}),
    "header_attest": ("header", {"instance_id": "request.instance_id", "execution_block_hash": ("request.exec_header_rlp", "keccak256")}),
    "header_write": ("header", {"instance_id": "record.instance_id", "execution_block_hash": "record.execution_block_hash"}),
    "job_write": ("job", {"instance_id": "job.instance_id", "job_id": "job.job_id"}),
    "header_check": ("header", {"instance_id": "instance_id", "execution_block_hash": "execution_block_hash"}),
    "hroot": ("hroot", {"instance_id": "instance_id", "root": "root"}),
}

# variant -> (account name, pda key, sender, writable, init, doc)
ATTEST_IX = {
    "Init": ("instance", "instance", None, True, True, "Root -> instance PDA. Permissionless, once per instance_id; instance_id must equal sha256(\"rfp021/instance-id\" || borsh(cfg) || trusted_block_root) and cfg must meet the floor (342 <= min_participation <= 512, ws_period_epochs <= 3558), else 1001. Bootstraps the light client, writes the first header + accumulator root."),
    "UpdateBegin": ("instance", "instance", None, False, False, "Root -> instance PDA. lc-core prepare_update + BLS pre-work; sends WriteJob."),
    "UpdateVerify": ("job", "job", None, True, False, "Root -> job PDA. Pairing check with the residue witness; consumes the job and sends Apply."),
    "Attest": ("header", "header_attest", None, False, False, "Root or chained -> header PDA. Verifies an Ethereum proof; replies to the caller (AttestReply) or emits the Attested event."),
    "WriteJob": ("job", "job_write", "instance PDA", True, True, "Internal: instance -> job PDA, write-once."),
    "Apply": ("instance", "instance", "job PDA", True, False, "Internal: job -> instance PDA; applies the verified update, sends WriteHeader/WriteRoot."),
    "WriteHeader": ("header", "header_write", "instance PDA", True, False, "Internal: instance -> header PDA; immutable record."),
    "WriteRoot": ("hroot", "hroot", "instance PDA", True, False, "Internal: instance -> header-root PDA, write-once."),
    "CheckRoot": ("hroot", "hroot", None, False, False, "Root or chained -> header-root PDA. 1101 unless root was an accumulator root of the instance."),
    "Update": ("instance", "instance", None, True, False, "Root -> instance PDA. Prepares, verifies the BLS residue witness and applies atomically; sends WriteHeader/WriteRoot. Same indexed non-signer hints and timestamp binding as UpdateBegin. Use UpdateBegin/UpdateVerify for updates exceeding the one-transaction gas budget."),
    "CheckHeader": ("header", "header_check", None, False, False, "Root or chained -> header PDA. 1101 unless the header record exists for (instance_id, execution_block_hash); 1204 if its chain_id or genesis_validators_root differ. Binds the anchor for consumers that verify inline with verify_at (optional pattern, CONSUMER-GUIDE.md)."),
}
ATTEST_ARGNAMES = {"Attest": ["request"], "WriteJob": ["job"], "WriteHeader": ["record"]}

CONS_PDA = {
    "vault": ("vault", {"vault_id": "vault_id"}),
    "nullifier_credit": ("nullifier", {"vault_id": "credit.vault_id", "statement_id": "credit.statement_id"}),
    "spend": None,  # raw 32-byte seed = the nullifier argument itself, no tag
}
CONS_IX = {
    "InitVault": ("vault", "vault", None, True, True, "Root -> vault PDA. Pins the attest instance, chain, token and Ethereum vault address."),
    "Claim": ("vault", "vault", None, False, False, "Root -> vault PDA. Chains Attest to the header PDA; the AttestReply lands back on the vault (on_attest_reply)."),
    "Nullify": ("nullifier", "nullifier_credit", "vault PDA", True, True, "Internal: vault -> nullifier PDA; fails 1250 if it exists. State = Credit."),
    "InitPrivateVault": ("vault", "vault", None, True, True, "Root -> vault PDA (erc20_receiver image only). State = PrivateVaultConfig."),
    "PrivateClaim": ("claimant", None, None, True, False, "Root -> the claimant's PRIVATE account. Verifies inline (attest_program::verify), credits denomination to its private balance (bound to cfg_hash), sends only RedeemCheck. 1001 unless the receiver is authorized (its owner's key)."),
    "RedeemCheck": ("vault", "vault", "this program's private actor", False, False, "Private actor -> public vault PDA. Checks cfg hash, chains CheckRoot to the attest root PDA and Spend to the nullifier PDA."),
    "Spend": ("nullifier", "spend", "vault PDA", True, True, "Internal: vault -> nullifier PDA (seed = the nullifier itself); fails 1250 if already spent."),
}
CONS_ARGNAMES = {"Nullify": ["credit"]}


def resolve_path(cv, args, path):
    """Check `path` ('arg' or 'arg.field') exists among the instruction args; return its type."""
    head, *rest = path.split(".")
    t = next(a["type"] for a in args if a["name"] == head)
    for f in rest:
        td = cv.types[t["defined"]]
        t = next(x["type"] for x in td["fields"] if x["name"] == f)
    return t


def build(prog):
    cv = Conv()
    if prog == "attest":
        enum, ix, argn, pdas, tag_prog = "Msg", ATTEST_IX, ATTEST_ARGNAMES, ATTEST_PDA, "attest"
        for t in ("InstanceState", "HeaderRecord", "Job", "AttestReply", "Statement", "Fact"):
            cv.define(t)
    else:
        enum, ix, argn, pdas, tag_prog = "ConsumerMsg", CONS_IX, CONS_ARGNAMES, CONS_PDA, "consumers"
        for t in ("VaultState", "PrivateVaultConfig", "Credit", "PrivateBalance", "AttestReply"):
            cv.define(t)
    cv.define(enum)
    seedinfo = {k: seed_fn(fn) for k, fn in SEEDS[tag_prog].items()}
    variants = cv.types[enum]["variants"]
    assert [v["name"] for v in variants] == [v for v in ix], f"{enum} variants changed: update the IDL tables in gen_idl.py\n  source: {[v['name'] for v in variants]}\n  idl:    {list(ix)}"
    instructions = []
    for i, v in enumerate(variants):
        acc, pkey, sender, writable, init, doc = ix[v["name"]]
        names = argn.get(v["name"])
        args = [{"name": (names[j] if names else f["name"]), "type": f["type"]} for j, f in enumerate(v["fields"])]
        a = {"name": acc, "writable": writable, "signer": False, "init": init, "visibility": ["public"]}
        if prog == "consumers" and v["name"] == "PrivateClaim":
            a["visibility"] = ["private_owned"]
        if pkey is not None and pdas.get(pkey) is not None:
            skey, paths = pdas[pkey]
            tag, params = seedinfo[skey]
            assert params == list(paths), f"seed fn params for {skey} changed: {params}"
            seeds = [{"kind": "const", "value": tag}]
            for p in params:
                path = paths[p]
                path, tr = path if isinstance(path, tuple) else (path, None)
                resolve_path(cv, args, path)
                s = {"kind": "arg", "path": path}
                if tr:
                    s["transform"] = tr
                seeds.append(s)
            a["pda"] = {"seeds": seeds}
        elif pkey == "spend":
            a["pda"] = {"seeds": [{"kind": "arg", "path": "nullifier"}]}
            resolve_path(cv, args, "nullifier")
        instr = {
            "name": re.sub(r"(?<!^)(?=[A-Z])", "_", v["name"]).lower(),
            "accounts": [a],
            "args": args,
            "execution": {"public": v["name"] != "PrivateClaim", "private_owned": v["name"] == "PrivateClaim"},
            "variant": v["name"],
            "variant_index": i,
            "doc": doc,
        }
        if sender:
            instr["internal"] = True
            instr["sender"] = sender
        instructions.append(instr)
    codes = error_codes()
    used = {n: c for n, c in codes.items() if prog == "attest" and n != "AlreadyClaimed" or prog == "consumers" and (n in ("Malformed", "PredicateFailed", "StatementMismatch", "AlreadyClaimed"))}
    idl = {
        "version": "0.1.0",
        "name": "rfp021_attest" if prog == "attest" else "rfp021_consumers",
        "instructions": instructions,
        "accounts": [],
        "types": [cv.types[k] for k in sorted(cv.types)],
        "errors": [{"code": c, "name": n, "msg": ERR_MSG[n]} for n, c in sorted(used.items(), key=lambda x: x[1])],
        "spec": "0.1.0",
        "metadata": {"name": "rfp021_attest" if prog == "attest" else "rfp021_consumers", "version": "0.1.0"},
        "instruction_type": "attest_program::Msg" if prog == "attest" else "consumers::ConsumerMsg",
    }
    # accounts = state layouts of the PDAs
    def acct(name, typ, doc, pkey=None):
        d = {"name": name, "type": cv.types[typ] if typ in cv.types else typ, "doc": doc}
        d["type"] = {k: v for k, v in d["type"].items() if k != "name"}
        return d
    if prog == "attest":
        idl["accounts"] = [
            acct("InstanceState", "InstanceState", "instance PDA: seed sha256('rfp021/instance' || instance_id). Immutable cfg + lc-core Store + header accumulator."),
            acct("HeaderRecord", "HeaderRecord", "header PDA: seed sha256('rfp021/header' || instance_id || execution_block_hash). Write-once, immutable."),
            acct("Job", "Job", "job PDA: seed sha256('rfp021/job' || instance_id || job_id u64 LE). Empty after UpdateVerify; the id can be reused."),
            {"name": "HeaderRoot", "type": {"kind": "struct", "fields": [{"name": "root", "type": {"array": ["u8", 32]}}]}, "doc": "root PDA: seed sha256('rfp021/hroot' || instance_id || root). State = the 32-byte root, write-once."},
        ]
        idl["events"] = [{"name": "Attested", "selector": sel("rfp021::Attested"), "data": {"defined": "AttestReply"}, "doc": "Emitted by a root-call Attest (no caller actor to reply to)."}]
        idl["notes"] = NOTE_ATTEST
    else:
        idl["accounts"] = [
            acct("VaultState", "VaultState", "vault PDA (erc20_receiver, eth_receiver): seed sha256('rfp021/vault' || vault_id). State = 0xA1 || borsh."),
            acct("PrivateVaultConfig", "PrivateVaultConfig", "vault PDA of a private vault (erc20_receiver image): same seed. State = 0xA2 || borsh(config); cfg_hash = sha256(borsh(config))."),
            acct("Credit", "Credit", "nullifier PDA of the public path: seed sha256('rfp021/nullifier/v2' || vault_id || statement_id). State = 0xA3 || borsh."),
            {"name": "SpentMarker", "type": {"kind": "struct", "fields": [{"name": "tag", "type": "u8"}]}, "doc": "nullifier PDA of the private path: seed = nullifier (raw 32 bytes); state = [0xA4]."},
            acct("PrivateBalance", "PrivateBalance", "claimant's (authorized) account state under this program. State = 0xA5 || borsh; one private vault config (cfg_hash) per account."),
        ]
        idl["callbacks"] = [{"name": "on_attest_reply", "message": {"defined": "AttestReply"}, "receiver": "vault PDA", "from": "attest program header PDA of the pinned instance", "doc": "Dispatched before ConsumerMsg when the sender is the attest program."}]
        idl["notes"] = NOTE_CONS
        pk = {k: seed_fn(fn) for k, fn in SEEDS["consumers"].items()}
        assert pk  # seed fns exist
    return idl


def sel(tag):
    assert f'b"{tag}"' in ALL, f"event tag {tag} not in source"
    return hashlib.sha256(tag.encode()).digest()[:8].hex()


NOTE_COMMON = (
    "Hand-written for LEZ v0.4 actor-model programs (see docs/DECISIONS.md D-MOD-4). Types, variants, "
    "field order, error codes and seed tags are generated from the Rust source by idl/gen_idl.py; "
    "one wire message type per program, borsh-encoded, enum tag = variant_index (u8). Extra keys "
    "(variant_index, doc, internal, sender, events, callbacks, notes, seed transform) are outside SPEL's "
    "schema and ignored by its serde types. PDA derivation differs from SPEL's documented one: here "
    "seed = sha256(const tag bytes || each part's raw bytes) (u64 = 8 bytes LE, no zero-padding to 32), "
    "address = AccountId::for_public_pda(program, seed). 'transform: keccak256' = keccak256 of the argument."
)
NOTE_ATTEST = NOTE_COMMON + " The instruction's single account is the RECEIVING actor; the sender (for internal messages) is checked in-guest."
NOTE_CONS = NOTE_COMMON + " eth_receiver and erc20_receiver share this message enum; eth_receiver pins token = 0xff..fe (EIP-7708) at InitVault and refuses InitPrivateVault. PDAs are derived under the consumer program id."


def main():
    check = "--check" in sys.argv
    bad = False
    for prog, fn in (("attest", "attest.idl.json"), ("consumers", "consumers.idl.json")):
        out = json.dumps(build(prog), indent=2) + "\n"
        p = ROOT / "idl" / fn
        if check:
            if not p.exists() or p.read_text() != out:
                print(f"DRIFT: {p} differs from the Rust source; run `python3 idl/gen_idl.py`")
                bad = True
            else:
                print(f"ok: {fn}")
        else:
            p.write_text(out)
            print(f"wrote {p}")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
