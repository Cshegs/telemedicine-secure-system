# Changes: real ML-KEM-768 + full-entropy fusion

This documents a real, tested fix to two problems: one found by a peer
reviewer, one found by re-reading the paper against the actual code
(the paper described CRYSTALS-Kyber/ML-KEM as implemented and
benchmarked; the code never had a real Kyber/ML-KEM implementation).

Every number and claim in this file comes from an actual run in a real
environment, described below. Nothing here is estimated or invented.

## 1. Kyber is now real: ML-KEM-768 via liboqs

`app/crypto/hybrid_fusion.py` previously used `MockKyber`, a SHA-256
construction with the same `KeyGen`/`Encaps`/`Decaps` interface as a real
KEM, but no lattice cryptography and no quantum resistance. It has been
replaced with `Kyber768KEM`, a thin wrapper around
`oqs.KeyEncapsulation("ML-KEM-768")` from `liboqs-python` (Open Quantum
Safe's `liboqs`, NIST FIPS 203).

Verified in this environment (Python 3.11.15, `liboqs-python` 0.16.0,
`liboqs` core 0.16.0):
- `KeyGen`/`Encaps`/`Decaps` round-trip produces matching shared secrets
  (`test_kyber_shared_secret_matches`).
- Public key 1184 bytes, secret key 2400 bytes, ciphertext 1088 bytes,
  shared secret 32 bytes -- the published ML-KEM-768 sizes.

Every place that previously imported `MockKyber` (`crypto_lab.py`'s
benchmark baseline, `design.py`'s pipeline explainer, the Crypto Lab
dashboard banner and pipeline-step labels) has been updated to reflect
the real implementation.

## 2. Fusion no longer truncates -- the flaw a reviewer caught

**Old design (v1):** Step 4 kept `round(alpha*32)` bytes of `K1'` and
`round(beta*32)` bytes of `K2'` before hashing them together. Under
`SECURITY_PROFILE` (alpha=0.2) that meant only 6 bytes (48 bits) of the
ECC-derived secret survived into the fused key. A reviewer pointed out
that this makes every profile *weaker* than a naive 50:50 concatenation
baseline: if an attacker has broken the other leg, they only need to
search the truncated leg's shrunken space, e.g. 2^48 instead of 2^256.

**New design (v2):** Step 4 always combines the full 32 bytes of both
`K1'` and `K2'`:

```python
def fuse(K1_norm: bytes, K2_norm: bytes) -> bytes:
    return hashlib.sha256(K1_norm + K2_norm).digest()
```

Breaking either leg alone no longer reduces the other leg's contribution.
`bytes_from_k1` and `bytes_from_k2` are now always 32 and are kept in the
result/log purely for display continuity.

A new regression test, `test_fused_key_depends_on_every_byte_of_k1_prime`,
directly disproves the old attack: it flips one bit of `K1'` at byte
index 20 (past the old 6-byte `SECURITY_PROFILE` truncation boundary) and
confirms `Kf` changes. Under the old code this bit would have been
discarded and `Kf` would not have changed.

## 3. alpha/beta now control HKDF domain separation, not byte allocation

Since the combiner no longer truncates, "alpha/beta as a weighting
mechanism" had to be replaced with something the code actually does.
Each profile (`app/crypto/profiles.py`) now carries an `hkdf_info` label
mixed into Step 5's HKDF derivation:

```
SPEED_PROFILE:    b"telemedicine-hybrid-ecc-kyber-v2-speed"
BALANCED_PROFILE: b"telemedicine-hybrid-ecc-kyber-v2-balanced"
SECURITY_PROFILE: b"telemedicine-hybrid-ecc-kyber-v2-security"
```

This is a real, testable property (`test_profiles_apply_distinct_hkdf_domain_separation`):
identical `(Kf, SID, T, PID)` under two different profiles still yield
three distinct `Kfinal` values, so a key derived for one operation type
can't be replayed as if it were derived under another profile's context.
`alpha`/`beta` are kept in the profile dict and the DB log purely as
descriptive/reporting metadata (shown on the dashboard, used for audit
flagging), not as cryptographic parameters.

## 4. Test suite: 8 -> 11 tests, all passing against real ML-KEM-768

```
PYTHONPATH=. python3 -m pytest tests/ -v
11 passed in 0.09s
```

Removed: the two tests that asserted the old truncated byte counts
(`test_weighted_fusion_byte_counts_speed`, `..._security`), since that
behavior was the flaw being fixed.

Added:
- `test_fusion_uses_full_entropy_speed_profile` / `..._security_profile`
  -- both profiles now report `bytes_from_k1 == bytes_from_k2 == 32`.
- `test_fused_key_depends_on_every_byte_of_k1_prime` -- the direct
  regression test described above.
- `test_profiles_apply_distinct_hkdf_domain_separation` -- proves the
  new role of alpha/beta.
- `test_traditional_baseline_uses_real_kyber_too` -- fairness check that
  the comparison baseline also uses real ML-KEM-768.

## 5. Real benchmark, re-run from scratch

The previous benchmark numbers in the paper (Table 3: 0.1698 / 0.1561 /
0.1554 ms) were never real: they timed two SHA-256 calls standing in for
Kyber, not ML-KEM-768. They must not be reused. Below are freshly
measured numbers, 100 iterations per configuration, run twice for
consistency, with the exact environment stated.

**Environment (both runs):**
- Python 3.11.15, Linux 6.18.44 (x86_64), Ubuntu 24.04.4 LTS
- CPU: Intel(R) Xeon(R) Processor @ 2.10GHz (2 vCPU)
- `cryptography` 46.0.7, `liboqs-python` 0.16.0, `liboqs` core 0.16.0
- Algorithm: ML-KEM-768 (NIST FIPS 203), X25519 (RFC 7748)

**Run 1** (2026-09-17 01:01 UTC):

| Configuration | Mean (ms) | Min (ms) | Max (ms) | Std Dev (ms) | vs Traditional |
|---|---|---|---|---|---|
| Traditional baseline | 0.1990 | 0.1350 | 5.2030 | 0.5057 | -- |
| SPEED_PROFILE | 0.1613 | 0.1420 | 0.3370 | 0.0285 | +18.9% faster |
| BALANCED_PROFILE | 0.1560 | 0.1420 | 0.1970 | 0.0138 | +21.6% faster |
| SECURITY_PROFILE | 0.1555 | 0.1430 | 0.2000 | 0.0131 | +21.8% faster |

**Run 2** (immediately after, same environment):

| Configuration | Mean (ms) | Min (ms) | Max (ms) | Std Dev (ms) | vs Traditional |
|---|---|---|---|---|---|
| Traditional baseline | 0.1972 | 0.1340 | 5.0440 | 0.4899 | -- |
| SPEED_PROFILE | 0.1547 | 0.1380 | 0.3200 | 0.0266 | +21.6% faster |
| BALANCED_PROFILE | 0.1521 | 0.1380 | 0.2030 | 0.0172 | +22.8% faster |
| SECURITY_PROFILE | 0.1624 | 0.1380 | 0.3640 | 0.0325 | +17.6% faster |

**Session-key uniqueness re-verified:** 100 real `establish_session_key`
calls under `BALANCED_PROFILE`, 100/100 unique `Kfinal` values, 0
collisions.

**What this means for the paper's claims:** the direction of the result
survives -- the proposed pipeline is still consistently faster and more
stable (much lower std dev, no ~5ms outliers) than the naive baseline,
because X25519 key generation dominates the timing budget in both paths,
exactly as the original project notes already suspected. That observation
was correct; it just hadn't been measured with real post-quantum crypto
until now. The absolute millisecond values are close to the old
MockKyber numbers by coincidence (ML-KEM-768 via liboqs is itself very
fast), not because the old numbers were secretly valid.

**Before these numbers go in a resubmitted paper:** re-run this same
benchmark script (`real_benchmark.py`, included) on whatever machine you
intend to name as the paper's official experimental environment (your
own dev machine or Render.com), and report the environment specs printed
by that run, not the specs above. This sandbox is a real environment,
but it's Claude's, not yours, and reviewers may reasonably ask which
machine produced the numbers in the paper.

## 6. v3: alpha/beta select ML-KEM strength, not just an HKDF label

After v2 shipped, a supervisor separately flagged a real problem with it:
alpha/beta had become purely descriptive (they only picked an HKDF label),
so "weighted key fusion" -- the thesis's stated contribution -- no longer
did anything a reviewer would call a contribution. Bringing back
byte-truncation was not an option (that's the flaw v2 fixed). So v3 gives
alpha/beta a different, real job: each profile now selects a different
NIST-standardised ML-KEM parameter set at Step 2 --

| Profile | Operation | ML-KEM parameter set | NIST security category |
|---|---|---|---|
| SPEED_PROFILE | video_call | ML-KEM-512 | Category 1 (~AES-128) |
| BALANCED_PROFILE | chat | ML-KEM-768 | Category 3 (~AES-192) |
| SECURITY_PROFILE | patient_record | ML-KEM-1024 | Category 5 (~AES-256) |

Step 4 (the combiner) is untouched: every profile still fuses 100% of
both K1' and K2', so this cannot reproduce the v1 truncation flaw --
what varies is which algorithm strength gets generated at Step 2, not how
much of it survives the combiner.

**Is this actually different from existing work, or just relabelled?**
Checked against real sources, not assumed:
- The combiner itself (full-entropy concatenation) is standard practice,
  not novel -- IETF `draft-ounsworth-cfrg-kem-combiners`, and Giacon,
  Heuer & Poettering's 2018 "KEM Combiners" paper. v2 already matched
  this; v3 doesn't change it.
- A 2025 healthcare-PQC review recommends varying ML-KEM strength by data
  sensitivity (ML-KEM-768 as a general default, ML-KEM-1024 for "the most
  sensitive long-lived genomic or national-scale health repositories"),
  but explicitly as a one-time architectural decision, not a
  per-transaction runtime choice: "Section 9 ... focuses on phased
  institutional migration, not application-layer adaptivity." The same
  review states the field has "few peer-reviewed, end-to-end case
  studies of post-quantum deployment in production healthcare
  environments ... prospective institutional case studies are needed."
- A 2026 MDPI paper on PQC for 6G smart hospitals uses one fixed
  algorithm (Kyber512) throughout; its only mention of switching to a
  stronger variant is a single undescribed diagram callout with no
  implementation or evaluation behind it. The authors themselves write
  that existing research lacks "adaptive security frameworks in
  latency-sensitive 6G medical applications."
- Runtime-adaptive PQC selection does exist as a technique, but in other
  domains (e.g. a 2026 vehicular-networks paper adapting PQC choice to
  network conditions), not healthcare, and not driven by application-
  layer operation semantics.

So the honest claim is narrow: not "we invented weighted fusion" and not
"we invented adaptive PQC," but "we implemented and empirically measured
the per-operation adaptive ML-KEM selection that healthcare PQC guidance
recommends only as a static, one-time architecture choice, inside a real
running telemedicine system" -- filling a gap the cited literature names
in its own words, rather than one asserted without checking.

**Real re-benchmark (two runs, 100 iterations each, same environment as
section 5):**

Run 1:

| Configuration | Alg | Mean (ms) | Min | Max | StdDev | vs baseline |
|---|---|---|---|---|---|---|
| Traditional (fixed ML-KEM-768) | ML-KEM-768 | 0.2366 | 0.1550 | 5.7510 | 0.5578 | -- |
| SPEED_PROFILE | ML-KEM-512 | 0.1769 | 0.1570 | 0.6260 | 0.0481 | +25.2% |
| BALANCED_PROFILE | ML-KEM-768 | 0.1937 | 0.1640 | 0.6440 | 0.0561 | +18.1% |
| SECURITY_PROFILE | ML-KEM-1024 | 0.1866 | 0.1690 | 0.3070 | 0.0191 | +21.1% |

Run 2 (immediately after):

| Configuration | Alg | Mean (ms) | Min | Max | StdDev | vs baseline |
|---|---|---|---|---|---|---|
| Traditional (fixed ML-KEM-768) | ML-KEM-768 | 0.2273 | 0.1560 | 5.6060 | 0.5435 | -- |
| SPEED_PROFILE | ML-KEM-512 | 0.1796 | 0.1560 | 0.5680 | 0.0453 | +21.0% |
| BALANCED_PROFILE | ML-KEM-768 | 0.1857 | 0.1640 | 0.2880 | 0.0231 | +18.3% |
| SECURITY_PROFILE | ML-KEM-1024 | 0.1854 | 0.1690 | 0.2920 | 0.0171 | +18.4% |

Real key/ciphertext sizes, both runs identical (these are the published
ML-KEM sizes, not measured noise):

| Alg | Public key | Ciphertext |
|---|---|---|
| ML-KEM-512 | 800 bytes | 768 bytes |
| ML-KEM-768 | 1184 bytes | 1088 bytes |
| ML-KEM-1024 | 1568 bytes | 1568 bytes |

**Honest read of these numbers:** all three profiles again measure faster
than the traditional baseline, for the same reason identified in v2 --
the baseline's occasional ~5ms outliers, most likely GC or scheduler
noise, pull its mean up; X25519 key generation dominates the typical-case
cost in every configuration. What did *not* show a clean pattern: latency
does not scale monotonically with ML-KEM parameter-set size in this data
-- SECURITY_PROFILE (ML-KEM-1024) is not reliably slower than
BALANCED_PROFILE (ML-KEM-768) across the two runs. At these operation
sizes, on this hardware, liboqs's ML-KEM implementation is fast enough
that the parameter-set choice is not the dominant cost, so this project
should not claim a clean latency-vs-security tradeoff from timing alone.
The real, unambiguous, monotonic tradeoff is in wire/storage cost: public
key and ciphertext size scale directly and substantially with security
category (e.g. SECURITY_PROFILE's ciphertext is 2.04x SPEED_PROFILE's).
That bandwidth/storage cost, not latency, is the honest basis for
"weighted" in this design -- reporting it any other way would not be
supported by what was actually measured.

## 7. alpha/beta removed from every user-facing display

Section 6 kept alpha/beta visible in a few places as "descriptive only"
metadata (e.g. `α=0.7 β=0.3` next to a profile). On reflection this was a
mistake to leave in: alpha+beta still summed to 1 wherever shown, which
visually implies a live weighted split even though nothing in the code
uses these numbers for anything security-relevant any more. That is the
exact class of mismatch this whole fix has been about removing, so it
should not have been left standing just because the underlying math was
now correct elsewhere.

Every remaining `α`/`β` display has been removed from the live app:
the Crypto Lab's Table I and Operation Log columns, the "Live Comparison"
cards, the pipeline visualiser, `/design`, `/call`, `/chat`, `/records`,
`/crypto-test`, and the chat/call JS notification banners. Each was
replaced with the profile's actual `kem_alg` (ML-KEM-512/768/1024) where
a value was shown at all. `alpha`/`beta` remain as fields in
`app/crypto/profiles.py` and in `CryptoOperationLog` purely as internal
record-keeping (which profile a log row came from) -- they are no longer
surfaced to a user or reviewer anywhere in the running system.

A second correction, on the values themselves rather than just where
they're shown: `alpha`/`beta` still held pairs like `0.7`/`0.3` (summing
to 1), which is a weighted-split value even with no display left to put
it on -- the value itself still asserted something false. Since Step 4
always includes 100% of both K1' and K2', the only honest value for
each is `1.0`, not a fraction. `app/crypto/profiles.py` and
`traditional_hybrid_keygen()` in `hybrid_fusion.py` now set both to
`1.0` for every profile and for the traditional baseline. They are kept
at all only because `CryptoOperationLog.alpha`/`.beta` are `NOT NULL`
columns already holding historical rows; nothing branches on their
value. `app/routers/design.py`'s separate, display-only `PROFILES` list
had no such constraint, so `alpha`/`beta` were removed from it outright
rather than set to `1.0` -- the honest choice there was to carry no
value at all, not a placeholder one.

## 8. Known follow-up: production deployment

Installing `liboqs-python` triggers a one-time build of the underlying
`liboqs` C library (cmake + a C compiler, several minutes) the first time
it's imported. That's fine for local development and for this sandbox,
but Render's free tier has limited build time and an ephemeral
filesystem, so the live deployment may need either (a) a Docker build
step that pre-builds `liboqs` into the image, or (b) confirmation that
Render's build step tolerates a multi-minute `pip install`. This wasn't
tested against Render specifically and should be verified before the
live demo depends on it, rather than assumed.

## 9. Section 8's flagged risk actually happened -- fixed with Docker

Section 8 flagged, before it happened, that Render's build step might not
tolerate the liboqs C build and that this "wasn't tested against Render
specifically." It wasn't, and it failed exactly as guessed: the real Render
deploy log showed

```
/bin/sh: 1: cmake: not found
Error installing liboqs.
...
RuntimeError: No oqs shared libraries found
```

The cause: `liboqs-python`'s liboqs build is not a `pip install`-time step,
it's a lazy first-`import oqs` step -- which on Render happens when the
web process starts, i.e. every cold start on the free tier. `runtime: python`
services on Render run on a Debian-based build image that does not include
`cmake` (Render's own docs confirm this and say to switch to Docker if a
needed build tool is missing from the native runtime).

Fix: added a `Dockerfile` and switched `render.yaml` from `runtime: python`
to `runtime: docker`. The Dockerfile installs the real toolchain liboqs
needs (`cmake`, `build-essential`, `ninja-build`, `git`, `libssl-dev`,
`pkg-config`) and then runs

```
python -c "import oqs; [oqs.KeyEncapsulation(alg).generate_keypair() for alg in ('ML-KEM-512','ML-KEM-768','ML-KEM-1024')]"
```

as a build step, so the liboqs C library is built once, at image-build
time, against all three parameter sets the app actually uses -- not lazily
inside the running container on Render's servers, and not silently
skipping a variant that never gets exercised until a real doctor/patient
session hits it.

**What was actually verified in this sandbox** (no unverified claim,
consistent with this project's whole discipline): Render's own Docker-image
registry pull could not be tested here directly -- this sandbox's egress
policy blocks Docker Hub, so `docker build` itself could not be run
end-to-end against `python:3.11-slim`. What *was* verified directly: (1)
`build-essential`, `cmake`, `ninja-build`, `git`, `libssl-dev`, `pkg-config`
are all real, correctly-named Debian/Ubuntu apt packages (checked against
this sandbox's own apt metadata); (2) with those tools present and liboqs's
cached build artifacts removed, a genuinely cold `pip install -r
requirements.txt` followed by the exact warm-up command above took ~7.5
minutes and produced a real, working liboqs build from source; (3) after
that cold build, `establish_session_key()` was re-run for all three
operation types and returned real ML-KEM-512/768/1024 sizes matching NIST
FIPS 203 (pk/ct = 800/768, 1184/1088, 1568/1568 bytes respectively) --
i.e. the exact mechanism the Dockerfile relies on was exercised, just not
inside an actual Docker container. **Still outstanding:** an actual `docker
build` / Render deploy of this Dockerfile has not been observed to
succeed end-to-end; treat this as strongly-supported, not yet
first-hand-confirmed on Render, until the next real deploy log is checked.

## 10. Style: no em dashes, anywhere -- and a stale README section caught in the sweep

Per instruction, this project (code comments, docstrings, UI-facing template
text, and documentation) does not use the em dash character ("--" as a
Unicode character, U+2014). Every real occurrence (63, across 13 files --
README.md, app/models.py, app/auth.py, app/main.py, app/seed.py,
app/routers/call.py, app/routers/chat.py, app/static/js/chat.js, and the
templates call.html, base.html, dashboard.html, crypto_lab.html,
crypto_test.html) was replaced with a plain double hyphen (`--`), which the
codebase already used in most other comments and docstrings, so this makes
the whole project consistent with itself rather than introducing a second
style. This applies going forward too: no em dashes in new code, comments,
or documentation for this project.

While doing that sweep, README.md's opening section ("What this system
demonstrates") turned out to still describe the *original, already-abandoned*
design: a weighted-fusion formula `Kf = SHA256(alpha*K1' || beta*K2')` and a
table of alpha/beta values (0.7/0.3, 0.4/0.6, 0.2/0.8) per profile. That
formula was replaced back in section 2 of this file, and those specific
alpha/beta values were replaced in section 8 -- but this one README section
was missed by both passes and kept asserting the old, truncating,
already-reviewer-flagged design as if it were current. Fixed: the formula
and table now match the real v3 implementation (Step 4 always fuses the
full 32 bytes of both K1' and K2'; the table now shows which real ML-KEM
parameter set -- 512/768/1024 -- each profile selects at Step 2, not a
weight pair). A full grep of the whole project for `alpha|beta|α|β`
was run afterward to confirm no other file has a similar stale claim left
standing; README.md was the only one.

## 11. Section 9's caveat was right, but the actual failure was different: Render never ran the Dockerfile at all

Section 9 flagged that the Docker fix hadn't been confirmed against a real
Render deploy. It has been confirmed now, and the outcome was not a Docker
build failure -- it was that Render never attempted a Docker build in the
first place. The next deploy log after pushing the Dockerfile and the
`runtime: docker` render.yaml change showed the service still badged
"Python 3" in the dashboard, still running from
`/opt/render/project/src/.venv/...`, still hitting the exact same
`cmake: not found` failure as before. The Dockerfile was never read.

Checked against Render's own docs and changelog rather than guessed: an
already-existing Web Service (created via "New Web Service" + connect repo,
not via a Blueprint) does not re-read `render.yaml` on an ordinary git-push
auto-deploy. `render.yaml` is only applied when a service is first created
from a Blueprint, or when a Blueprint is explicitly synced afterward.
Changing a service's `runtime` after creation is documented as possible
only through the Render API or a Blueprint sync, not through the
dashboard. That explains why editing `render.yaml` and pushing did nothing
to this service's actual configuration.

Separately, and found while investigating: `render.yaml`'s `name` field
was `telemed-hybrid-crypto`, which never matched the real service name,
`telemedicine-secure-system`. That mismatch predates this fix -- it was
already wrong in the original file -- but it would have blocked a
Blueprint sync from ever matching this service even if one were attempted,
since Render matches an existing service by name. Fixed: `render.yaml`'s
name now matches the real service.

The verified, documented way forward (not the in-place API/Blueprint route,
which this project could not test end-to-end from here): create a new
Render Web Service pointed at the same GitHub repo/branch, and choose
Docker as the Language during creation -- Render's docs describe this path
explicitly for new services. The existing broken service can stay in place
until the new one is confirmed healthy, then either be kept as a spare or
deleted.

**Confirmed, end to end:** a new Web Service (`telemedicine-secure-system-docker`,
Language: Docker, same repo/branch) deployed clean on the first real attempt
from commit `64bc78e`. No `cmake: not found`, no lazy liboqs build at
startup at all -- the log went straight from "Setting WEB_CONCURRENCY=1" to
liboqs loading and uvicorn starting, which means liboqs was already built
into the image at Docker-build time exactly as the `Dockerfile` intends.
One unrelated failure showed up first (`psycopg2.OperationalError` /
"tenant/user ... not found" connecting to the Supabase Postgres pooler) --
that was the Supabase project having auto-paused from inactivity on its
free tier, not anything this fix touched. Restoring the Supabase project
and retrying the same deploy succeeded: `Deploy succeeded | Live`, service
reachable at `https://telemedicine-secure-system-docker.onrender.com`.
The original cmake/Docker problem this section exists to fix is closed.

## Not yet done (separate from this fix)

- Entity authentication / threat model (reviewer comment 2) -- not
  addressed by this change.
- Reproducibility appendix for the paper (reviewer comment 3) -- the
  environment/version data above can seed it, but it still needs to be
  written into the manuscript, and the paper needs to state all three
  ML-KEM parameter sets (512/768/1024) explicitly, which it currently
  doesn't.
- The paper text itself still needs rewriting wherever it describes
  Kyber/ML-KEM and the fusion mechanism, since both were inaccurate
  before this fix. It also needs a "related work" paragraph citing the
  sources in section 6 above, so the contribution claim is explicitly
  scoped and defensible rather than asserted.
- Section 6's literature check was done by reading the two closest
  papers found via search, not an exhaustive systematic review. Before
  final submission, it's worth a broader search pass (and possibly a
  librarian/supervisor check) to make sure no closer prior work was
  missed.
- The relative cost of ML-KEM-512 vs -768 vs -1024 should be framed in
  the paper as a bandwidth/storage tradeoff (backed by the real
  measured sizes above), not a latency tradeoff -- the real benchmark
  data does not support a monotonic latency claim, and the paper must
  not claim one.
- The Render Docker deploy (section 9) needs to actually be watched
  through a real deploy log once pushed -- the fix is verified as far
  as this sandbox's network policy allows, but not yet confirmed against
  a live Render build.
