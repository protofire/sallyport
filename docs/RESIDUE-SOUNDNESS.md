# Residue check: soundness and completeness

Decision `D-ATT-2`. Code: `crates/attest-program/src/residue.rs`, `bls.rs`, `witness.rs`. Test: `crates/attest-program/tests/residue_differential.rs`.

## Notation

`u = |x| = 0xd201000000010000` (BLS12-381 has `x = -u`). `r = u^4 - u^2 + 1`, `p = (u+1)^2 r/3 - u`, `N = p^12 - 1`, `h = N/r`. `λ = p + u = p - x`. `Fp12 = Fp6[w]/(w^2 - v)`. blst stores it as `fp6[0] + fp6[1]·w`, so elements with `fp6[1] = 0` form the subfield `Fp6`.

## What the guest checks

`bls::pairing_check` (bls.rs:176) computes `f = blst_miller_loop_n([H(m), sig], [apk, -G1])` (bls.rs:184-213) in the guest. The relayer supplies only the 864-byte witness `(c, s)`. `residue::check(f, witness)` (residue.rs:44-72) accepts iff all of these hold:

1. `len = 864` (residue.rs:45);
2. each of the 18 limbs is a canonical big-endian `Fp` element `< p` (residue.rs:31-38). `c` is 12 limbs; `s` is 6 limbs placed in `fp6[0]` with `fp6[1] = 0` (residue.rs:20, 49), so `s ∈ Fp6`;
3. `c ≠ 0` (residue.rs:53);
4. `c^p · c^u = f · s`. `c^u` is a square-and-multiply loop over `u` with generic `Fp12` squaring (residue.rs:56-66), and `c^p` is `blst_fp12_frobenius_map(c, 1)` (residue.rs:69-71). The equation is therefore **`c^λ = f·s`**.

## Facts used

All checked with exact integers (2026-11-12):

- (F1) `λ = r·(u+1)^2/3`, so `r | λ`. This holds because `p - x = (x-1)^2 r/3` for the BLS12 family.
- (F2) `r | p^4 - p^2 + 1`, which divides `p^6 + 1`. Hence `(p^6 - 1) | h`.
- (F3) `gcd(λ, N) = r·(u+1)`. So `λ` is not coprime to `h`, which is why a scaling factor is needed.
- (F4) `d = 27·(u+1)/3 = 9(u+1)` and `m = h/d` satisfy `d | h`, `gcd(d, m) = 1`, `gcd(λ, m) = 1` and `d | p^6 - 1`. `v3(h) = 3` and `v3(u+1) = 1`, so `d` takes all of the 3-part of `h` (the 27th roots of unity) together with the `u+1` part of the gcd.
- (F5) `blst_final_exp(f) = f^(3h)`. (asserted by the test). `f^h` lies in `μ_r` because `(f^h)^r = f^N = 1`, and `gcd(3, r) = 1`, so `final_exp_is_one(f) ⟺ f^h = 1`.

## Soundness

**Claim.** If `check(f, witness)` returns true, then `f^h = 1`. This is exactly blst's verification condition `final_exp(f) = 1` (F5), so `e(apk, H(m)) · e(-G1, sig) = 1`, i.e. `e(apk, H(m)) = e(G1, sig)`.

**Proof.** `c ≠ 0` gives `c ∈ Fp12^*`, so `c^N = 1`. Then `c^λ ≠ 0`, so `s ≠ 0` and `s ∈ Fp6^*`, which gives `s^(p^6-1) = 1`. Raise `c^λ = f·s` to the power `h`:
`f^h = c^(λh) · s^(-h) = c^((λ/r)·N) · 1 = 1`, using (F1) for `λ/r ∈ Z` and (F2) for `s^h = 1`. ∎

No property of `f` and no gcd condition is used (those matter only for completeness). It relies on `c ≠ 0`, `s` confined to the subfield `Fp6`, and `f` computed by the guest rather than supplied by the relayer. Without `c ≠ 0`, `c = s = 0` would satisfy the homogeneous equation for any `f`. Canonicity (step 2) is not needed for soundness; it makes the encoding injective.

## Completeness

**Claim.** If `f^h = 1`, then `witness::make` (witness.rs:45-66) returns `(c, s)` that passes the check.

Let `e = m·(m^(-1) mod d)`, so that `e ≡ 1 (mod d)` and `e ≡ 0 (mod m)`. The builder computes `s = f^(h-e) = f^(-e)` (witness.rs:58-59). Since `ord f | h = d·m` with `gcd(d,m) = 1` (F4), `f^e` is the `d`-component of `f`. Its order divides `d`, and `d | p^6-1`. `Fp12^*` is cyclic, so its unique subgroup of order `d` lies inside `Fp6^*`. Hence `s ∈ Fp6^*`, which witness.rs:60 asserts. Next, `f·s = f^(1-e)` has order dividing `m`, and `gcd(λ, m) = 1` (F4). So `c = (f·s)^(λ^(-1) mod m)` (witness.rs:61) satisfies `c^λ = f·s` and `c ≠ 0`. Encoding with `blst_bendian_from_fp` (witness.rs:27-42) is canonical. The builder re-runs `check` before returning (witness.rs:65). If `f^h ≠ 1`, it returns `None` (witness.rs:46).

Witnesses are not unique (any `ζ` with `ζ^λ ∈ Fp6^*` gives another pair); harmless, as the witness only feeds `pairing_check` (program.rs:175, 226) and is hashed into no id.

## Relation to the literature

Residue witness of Novakovic–Eagen, "On Proving Pairings" (ePrint 2024/640), which instantiates it for BN254 with a 27th-root-of-unity scaling factor. Here `λ = p - x` and `s` ranges over `Fp6^*`; the proof above is self-contained (no lemma of the paper is used; its section numbers were not re-checked).

## Input validation the conclusion depends on

The soundness claim gives `f^h = 1` for whatever `f` the guest computed. Reading that as the BLS equation needs valid pairing inputs:

| Input | Requirement | Enforced |
|---|---|---|
| `sig` | on curve, in G2, not ∞, equal to the authenticated signature bytes | bls.rs:146-153; hint bound by recompression bls.rs:55-70 |
| `H(m)` | in G2 | `blst_hash_to_g2` with the eth2 POP DST, cofactor cleared (bls.rs:156-165). `signing_root` comes from `lc_core::prepare_update` |
| `apk` | = stored aggregate − non-signers (from `sync_committee_bits`), on curve, not ∞ | bls.rs:110-144; hints bound by recompression bls.rs:30-50 |
| committee keys | in G1 | **not checked in-guest**: see Findings (R-2) |
| `(apk, h, sig)` across Begin/Verify | from program-owned Job state, re-deserialized with an on-curve check | program.rs:219-226; bls.rs:193-195 |
| witness | items 1-3 above | residue.rs:45-53 |

## Findings

- **R-1 (OK).** The code implements exactly the equation the proof needs, with every check it relies on. Removing the canonicity or `c ≠ 0` check makes the differential test fail (mutation run 2026-11-12).
- **R-2 (Info, trust assumption).** Committee keys and the aggregate are never subgroup-checked in the guest. Only ∞ is rejected (`check_committee_len`, lc-core `sync.rs:106`, D-LC-5). D-LC-5 calls this a stand-in for KeyValidate, but it covers only the ∞ part. G1 membership rests on Ethereum's deposit-time PoP check and the SSZ-authenticated committee (inside the light-client trust model). The residue proof is unaffected; only the bilinear reading of `f^h = 1` needs `apk ∈ G1`.
- **R-3 (Info, coverage).** The differential test uses host crates.io blst, not the guest's `risc0/blst` fork; the fork is covered only by the guest self-test (`crates/spec-tests`).
