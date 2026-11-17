//! ethereum/bls12-381-tests (pinned in fetch.sh) through the production BLS path:
//! host = lc-core `BlstVerifier` + attest-program `bls.rs` (crates.io blst); guest = the same
//! `bls.rs` in the zkVM (risc0 blst fork, SPEC_SELFTEST_ELF); ABI = LEZ executor UpdateBegin.
//! Each bls.rs run goes through both hint shapes (K: guest decompresses; K+2: relayer hints).
//! Run: SPEC_TESTS_DIR=~/spectests cargo test --release -p spec-tests --test bls -- --nocapture

use attest_program::InstanceState;
use blst::min_pk::{AggregatePublicKey, PublicKey};
use lc_core::host_bls::BlstVerifier;
use lc_core::{PairingInputs, SigVerifier};
use program_tests::{
    force_instance, sepolia_init, sepolia_updates, Chain, SEPOLIA_ID, SEPOLIA_NOW,
};
use serde_json::Value;
use spec_tests::*;

const H2C_DST: &[u8] = b"QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_";

fn load(suite: &str) -> Vec<(String, Value)> {
    let d = dir().join("bls").join(suite);
    let mut v: Vec<_> = std::fs::read_dir(&d)
        .unwrap_or_else(|e| panic!("{}: {e}", d.display()))
        .map(|e| e.unwrap().path())
        .collect();
    v.sort();
    v.into_iter()
        .map(|p| {
            let s = std::fs::read_to_string(&p).unwrap();
            (
                p.file_stem().unwrap().to_str().unwrap().to_string(),
                serde_json::from_str(&s).unwrap(),
            )
        })
        .collect()
}

fn fixed<const N: usize>(v: &Value) -> Option<[u8; N]> {
    v.as_str()
        .and_then(|s| hex::decode(s.trim_start_matches("0x")).ok())
        .and_then(|b| b.try_into().ok())
}

/// Collects guest ops and how to classify each result into the tally.
type Check = Box<dyn Fn(&mut Tally, &str, &[u8])>;

#[derive(Default)]
struct Guest {
    ops: Vec<Op>,
    want: Vec<(String, Check)>,
}

impl Guest {
    fn push(&mut self, id: String, op: Op, ok: impl Fn(&[u8]) -> bool + 'static) {
        self.check(id, op, move |t, id, got| {
            if ok(got) {
                t.pass()
            } else {
                t.mismatch(format!("guest {id}: {}", hex::encode(got)))
            }
        });
    }
    fn check(&mut self, id: String, op: Op, c: impl Fn(&mut Tally, &str, &[u8]) + 'static) {
        self.ops.push(op);
        self.want.push((id, Box::new(c)));
    }
    fn run(self) -> Tally {
        let mut t = Tally::default();
        for ((id, c), got) in self.want.iter().zip(guest(&self.ops)) {
            c(&mut t, id, &got);
        }
        t
    }
}

/// Signature checks (verify / mapped fast_aggregate_verify) on host and guest, both hint shapes.
fn sig_case(id: &str, p: PairingInputs, want: bool, host: &mut Tally, g: &mut Guest) {
    let w = witness(&p);
    let (kh, k2) = hint_sets(&p);
    let v = BlstVerifier.verify_sync_aggregate(
        &p.aggregate_pubkey,
        &p.non_signer_pubkeys,
        &p.signing_root,
        &p.signature,
    );
    let (a, b) = (bls_host(&p, &kh, &w), bls_host(&p, &k2, &w));
    if v == want && (a == 2) == want && (b == 2) == want {
        host.pass()
    } else {
        host.mismatch(format!(
            "{id}: want {want}, BlstVerifier {v}, bls.rs K {a} K+2 {b}"
        ));
    }
    for (tag, h) in [("K", kh), ("K+2", k2)] {
        g.push(
            format!("{id} {tag}"),
            Op::Bls(p.clone(), h, w.clone()),
            move |r| (r == [2]) == want,
        );
    }
}

fn unsupported_rows(t: &mut Tally, n: usize, why: &str) {
    for _ in 0..n {
        t.unsupported(why);
    }
}

#[test]
fn bls_signatures() {
    let (mut vh, mut fh, mut ah) = (Tally::default(), Tally::default(), Tally::default());
    let (mut vg, mut fg) = (Guest::default(), Guest::default());
    let (mut v_abi, mut f_abi, mut a_abi) = (Tally::default(), Tally::default(), Tally::default());
    let abi_why = "LEZ ABI: message is always a signing_root of an attested header";

    for (id, c) in load("verify") {
        let i = &c["input"];
        let (Some(pk), Some(msg), Some(sig)) = (
            fixed(&i["pubkey"]),
            fixed(&i["message"]),
            fixed(&i["signature"]),
        ) else {
            vh.unsupported("encoding not 48/32/96 bytes (borsh fixed fields)");
            continue;
        };
        let p = PairingInputs {
            aggregate_pubkey: pk,
            non_signer_pubkeys: vec![],
            signing_root: msg,
            signature: sig,
        };
        sig_case(&id, p, c["output"].as_bool().unwrap(), &mut vh, &mut vg);
        v_abi.unsupported(abi_why);
    }

    // FastAggregateVerify(pks) as the sync check computes it: committee aggregate (harness plays
    // consensus' eth_aggregate_pubkeys over pks + one extra member X) minus non-signer X.
    let x: [u8; 48] = {
        let mut o = [0u8; 48];
        // SAFETY: 48-byte buffer, static generator.
        unsafe { blst::blst_p1_affine_compress(o.as_mut_ptr(), blst::blst_p1_affine_generator()) };
        o
    };
    for (id, c) in load("fast_aggregate_verify") {
        let i = &c["input"];
        f_abi.unsupported(
            "LEZ ABI: committee is SSZ-authenticated (bootstrap branch), not an arbitrary set",
        );
        let (Some(msg), Some(sig)) = (fixed::<32>(&i["message"]), fixed::<96>(&i["signature"]))
        else {
            fh.unsupported("signature not 96 bytes (borsh [u8; 96])");
            continue;
        };
        let pks: Vec<Option<[u8; 48]>> =
            i["pubkeys"].as_array().unwrap().iter().map(fixed).collect();
        let inf = {
            let mut b = [0u8; 48];
            b[0] = 0xc0;
            b
        };
        if pks.contains(&Some(inf)) {
            fh.unsupported(
                "infinity member refused at committee admission (D-LC-5, 1001) before any BLS",
            );
            continue;
        }
        let pts: Option<Vec<PublicKey>> = pks
            .iter()
            .map(|k| k.and_then(|k| PublicKey::uncompress(&k).ok()))
            .collect();
        let Some(mut pts) = pts else {
            fh.unsupported("member key not decodable: refused at committee admission");
            continue;
        };
        pts.push(PublicKey::uncompress(&x).unwrap());
        let refs: Vec<&PublicKey> = pts.iter().collect();
        let agg = AggregatePublicKey::aggregate(&refs, false)
            .unwrap()
            .to_public_key()
            .compress();
        let p = PairingInputs {
            aggregate_pubkey: agg,
            non_signer_pubkeys: vec![x],
            signing_root: msg,
            signature: sig,
        };
        sig_case(&id, p, c["output"].as_bool().unwrap(), &mut fh, &mut fg);
    }

    let n = load("aggregate_verify").len();
    unsupported_rows(
        &mut ah,
        n,
        "distinct message per key: a sync aggregate signs one signing root",
    );
    unsupported_rows(
        &mut a_abi,
        n,
        "distinct message per key: a sync aggregate signs one signing root",
    );

    let (vg, fg) = (vg.run(), fg.run());
    report(
        "BLS signatures (bls12-381-tests)",
        &[
            ("verify host".into(), &vh),
            (
                "verify guest (zkVM bls.rs, K + K+2, residue witness)".into(),
                &vg,
            ),
            ("verify LEZ ABI".into(), &v_abi),
            ("fast_aggregate_verify host".into(), &fh),
            (
                "fast_aggregate_verify guest (zkVM bls.rs, K + K+2)".into(),
                &fg,
            ),
            ("fast_aggregate_verify LEZ ABI".into(), &f_abi),
            ("aggregate_verify host".into(), &ah),
            ("aggregate_verify guest/ABI".into(), &a_abi),
        ],
    );
}

#[test]
fn bls_hash_to_g2() {
    let (mut h, mut g, mut abi) = (Tally::default(), Guest::default(), Tally::default());
    for (id, c) in load("hash_to_G2") {
        let msg = c["input"]["msg"].as_str().unwrap().as_bytes().to_vec();
        // blst serialization: x.c1 ‖ x.c0 ‖ y.c1 ‖ y.c0 (big-endian); vectors give "c0,c1"
        let coord = |k: &str| {
            let s = c["output"][k].as_str().unwrap();
            let (c0, c1) = s.split_once(',').unwrap();
            let f = |x: &str| hex::decode(x.trim().trim_start_matches("0x")).unwrap();
            [f(c1), f(c0)].concat()
        };
        let want = [coord("x"), coord("y")].concat();
        let mut out = [0u8; 192];
        // SAFETY: live buffers; same blst call the production `bls::prepare` makes (eth2 DST there).
        unsafe {
            let (mut p, mut a) = (blst::blst_p2::default(), blst::blst_p2_affine::default());
            blst::blst_hash_to_g2(
                &mut p,
                msg.as_ptr(),
                msg.len(),
                H2C_DST.as_ptr(),
                H2C_DST.len(),
                core::ptr::null(),
                0,
            );
            blst::blst_p2_to_affine(&mut a, &p);
            blst::blst_p2_affine_serialize(out.as_mut_ptr(), &a);
        }
        if out[..] == want[..] {
            h.pass()
        } else {
            h.mismatch(format!("{id}: host"))
        }
        let w2 = want.clone();
        g.push(id, Op::HashToG2(msg, H2C_DST.to_vec()), move |r| {
            r == &w2[..]
        });
        abi.unsupported(
            "LEZ ABI: DST fixed to the eth2 POP DST, message is a 32-byte signing root",
        );
    }
    let g = g.run();
    report(
        "hash_to_G2 (bls12-381-tests)",
        &[
            ("hash_to_G2 host (crates.io blst)".into(), &h),
            ("hash_to_G2 guest (risc0 blst fork)".into(), &g),
            ("hash_to_G2 LEZ ABI".into(), &abi),
        ],
    );
}

/// Our results that deliberately differ from a deserialization vector (name, our acceptance, why).
const BY_DESIGN: &[(&str, &str, bool, &str)] = &[
    ("G1", "deserialization_fails_not_in_G1", true,
     "by design: committee aggregate is SSZ-authenticated (eth_aggregate_pubkeys of KeyValidated deposit keys), no in-guest G1 subgroup check (bls.rs prepare doc, DECISIONS D-LC-5)"),
    ("G1", "deserialization_succeeds_infinity_with_true_b_flag", false,
     "by design: infinity aggregate key refused (D-LC-5 admission; prepare rejects infinity apk); KeyValidate also rejects it"),
    ("G2", "deserialization_succeeds_infinity_with_true_b_flag", false,
     "by design: infinity signature refused in prepare (cannot verify against a non-infinity apk; same final outcome as FastAggregateVerify)"),
];

fn classify(t: &mut Tally, group: &str, id: &str, path: &str, want: bool, got: bool) {
    if got == want {
        return t.pass();
    }
    match BY_DESIGN
        .iter()
        .find(|(g, n, ours, _)| *g == group && *n == id && *ours == got)
    {
        Some((_, _, _, why)) => t.unsupported(*why),
        None => t.mismatch(format!("{path} {id}: want {want}, accepted {got}")),
    }
}

#[test]
fn bls_deserialization() {
    let pk_ok: [u8; 48] = fixed(
        &load("deserialization_G1")
            .into_iter()
            .find(|(n, _)| n == "deserialization_succeeds_correct_point")
            .unwrap()
            .1["input"]["pubkey"],
    )
    .unwrap();
    let sig_ok: [u8; 96] = fixed(
        &load("deserialization_G2")
            .into_iter()
            .find(|(n, _)| n == "deserialization_succeeds_correct_point")
            .unwrap()
            .1["input"]["signature"],
    )
    .unwrap();

    // LEZ executor, real Sepolia instance and update (UpdateBegin = decode + subgroup/infinity checks).
    let mut c = Chain::new();
    c.init(&sepolia_init()).unwrap();
    let base: InstanceState = c.instance_state(&SEPOLIA_ID);
    let u0 = sepolia_updates()[1].clone();
    let mut job = 100u64;
    let mut begin =
        |c: &mut Chain, st: &InstanceState, u: &lc_core::LightClientUpdate| -> (bool, bool) {
            force_instance(c, SEPOLIA_ID, st);
            let k2 = c.hints(SEPOLIA_ID, u, SEPOLIA_NOW);
            let k = k2[..k2.len() - 2].to_vec();
            let mut r = [false; 2];
            for (i, h) in [k, k2].into_iter().enumerate() {
                job += 1;
                r[i] = c.begin_hinted(SEPOLIA_ID, job, u, SEPOLIA_NOW, h).is_ok();
            }
            (r[0], r[1])
        };

    let mut rows: Vec<(String, Tally)> = vec![];
    for (group, suite) in [("G1", "deserialization_G1"), ("G2", "deserialization_G2")] {
        let (mut h, mut g, mut abi) = (Tally::default(), Guest::default(), Tally::default());
        for (id, cs) in load(suite) {
            let want = cs["output"].as_bool().unwrap();
            let p = if group == "G1" {
                fixed::<48>(&cs["input"]["pubkey"]).map(|pk| PairingInputs {
                    aggregate_pubkey: pk,
                    non_signer_pubkeys: vec![],
                    signing_root: [0; 32],
                    signature: sig_ok,
                })
            } else {
                fixed::<96>(&cs["input"]["signature"]).map(|s| PairingInputs {
                    aggregate_pubkey: pk_ok,
                    non_signer_pubkeys: vec![],
                    signing_root: [0; 32],
                    signature: s,
                })
            };
            let Some(p) = p else {
                for t in [&mut h, &mut abi] {
                    t.unsupported("wrong length: not representable in borsh fixed-size field (relayer decode rejects, 1001)");
                }
                continue;
            };
            // host bls.rs: accepted = passes prepare (decode, on-curve, recompression, G2 subgroup, non-infinity)
            let (kh, k2) = hint_sets(&p);
            let zero = vec![0u8; 864];
            for (tag, hints) in [("K", kh), ("K+2", k2)] {
                classify(
                    &mut h,
                    group,
                    &id,
                    &format!("host {tag}"),
                    want,
                    bls_host(&p, &hints, &zero) >= 1,
                );
                let (gid, w) = (id.clone(), want);
                g.check(
                    format!("{id} {tag}"),
                    Op::Bls(p.clone(), hints, zero.clone()),
                    move |t, _, r| classify(t, group, &gid, "guest", w, r[0] >= 1),
                );
            }
            // LEZ ABI: G1 bytes as the stored committee aggregate; G2 bytes as the update signature
            let mut st = base.clone();
            let mut u = u0.clone();
            if group == "G1" {
                st.store.current_sync_committee.aggregate_pubkey = p.aggregate_pubkey;
                if let Some(n) = st.store.next_sync_committee.as_mut() {
                    n.aggregate_pubkey = p.aggregate_pubkey;
                }
            } else {
                u.sync_aggregate.sync_committee_signature = p.signature;
            }
            let (a, b) = begin(&mut c, &st, &u);
            classify(&mut abi, group, &id, "LEZ K", want, a);
            classify(&mut abi, group, &id, "LEZ K+2", want, b);
        }
        rows.push((
            format!("deserialization_{group} host (bls.rs prepare, K + K+2)"),
            h,
        ));
        rows.push((
            format!("deserialization_{group} guest (zkVM bls.rs prepare, K + K+2)"),
            g.run(),
        ));
        rows.push((
            format!("deserialization_{group} LEZ ABI UpdateBegin (K + K+2)"),
            abi,
        ));
    }
    report(
        "BLS deserialization (bls12-381-tests)",
        &rows.iter().map(|(n, t)| (n.clone(), t)).collect::<Vec<_>>(),
    );
}
