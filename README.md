# TeleMedSecure -- Hybrid ECC–Kyber Telemedicine Platform

**Final-year Computer Science project · Anchor University Lagos**

Research paper: *"Design of a Context-Aware Hybrid ECC–Kyber Cryptographic Framework
with Secure Key Fusion for Telemedicine Information Security."*

---

## What this system demonstrates

The paper's central contribution is a **six-step hybrid key fusion pipeline** that
combines classical ECC (X25519) with post-quantum ML-KEM (CRYSTALS-Kyber), where
each operation type selects a different real ML-KEM parameter set:

```
Step 1: ECC X25519 key exchange          -> K1
Step 2: ML-KEM key encapsulation         -> K2   (512 / 768 / 1024, profile-selected)
Step 3: SHA-256 normalisation            -> K1', K2'
Step 4: Full-entropy fusion              -> Kf = SHA256(K1' || K2')
Step 5: HKDF context derivation          -> Kfinal = HKDF(Kf || SID || T || PID)
Step 6: AES-256-GCM encryption           -> C
```

Step 4 always combines the full 32 bytes of both K1' and K2' for every profile
(no truncation, no weighting -- see `CHANGES.md` for why an earlier weighted-byte
design was replaced). What actually varies per operation type is which ML-KEM
parameter set gets generated at Step 2:

| Feature | Profile | ML-KEM parameter set | Rationale |
|---|---|---|---|
| Video call session | SPEED_PROFILE | ML-KEM-512 | Live calls cannot tolerate slow key setup |
| Secure chat | BALANCED_PROFILE | ML-KEM-768 | Also the fixed baseline algorithm; fairest comparison point |
| Patient records | SECURITY_PROFILE | ML-KEM-1024 | Long-lived data must resist future quantum attacks |

**Every real user action (sending a message, saving a record, starting a call) runs
the pipeline live and logs the result** -- making the paper's Table I a continuously
demonstrable feature of the running system.

---

## Honest scope: what is and isn't encrypted by the hybrid framework

- **Patient records** -- encrypted end-to-end with `Kfinal` via AES-256-GCM. ✓
- **Chat messages** -- each message encrypted with a fresh `Kfinal`. ✓
- **Video/audio streams** -- encrypted natively by WebRTC (DTLS-SRTP), which is
  industry-standard and runs automatically in the browser. The hybrid framework
  secures the **call session record** (who called whom, when) generated with
  SPEED_PROFILE before the WebRTC handshake begins. This demonstrates the
  speed-priority trade-off honestly without overstating what the prototype replaces.

---

## Running locally

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open **http://localhost:8000** -- demo credentials are shown on the login page.

### Demo accounts (password for all: `demo1234`)

| Role | Username | Full name |
|---|---|---|
| Doctor | adaeze | Dr. Adaeze Nwosu |
| Doctor | tunde | Dr. Tunde Bakare |
| Patient | amara | Amara Okafor |
| Patient | chidinma | Chidinma Obi |
| Patient | bashir | Bashir Lawal |
| Patient | ngozi | Ngozi Eze |

---

## Features

| Route | Description |
|---|---|
| `/dashboard` | Role-based dashboard (doctor: patient list + stats; patient: records + doctor card) |
| `/records` | Doctor creates encrypted patient records; patient views own records |
| `/chat` | Real-time WebSocket chat -- each message encrypted with BALANCED_PROFILE |
| `/call` | WebRTC video call -- SPEED_PROFILE pipeline runs before WebRTC handshake |
| `/crypto-lab` | **Crypto Transparency Dashboard** -- live log, Chart.js comparison chart, pipeline step visualiser, "Run Live Comparison" button |
| `/crypto-test` | Quick manual pipeline test -- fire any profile and inspect raw JSON output |

---

## Crypto Lab (for examiners)

The **Crypto Lab** (`/crypto-lab`) is the core examiner-facing feature. It shows:

1. **Live operation log** -- every call to `establish_session_key()` (triggered by real
   user actions) appears here with operation type, the ML-KEM parameter set that
   profile selected (512/768/1024), K1′/K2′/Kf previews, and execution time.
2. **Comparison chart** -- Chart.js bar chart of average execution time per profile,
   built from actual logged history -- the live version of Table I from the paper.
3. **"Run Live Comparison" button** -- fires all three profiles back-to-back and shows
   timing side-by-side in real time. Click this during a defence to demonstrate the
   speed/security trade-off on demand.
4. **Pipeline step visualiser** -- shows Steps 1–6 for the most recent operation with
   hex previews at each step (K1′, K2′, Kf, SID).

---

## Deployment (Render.com free tier)

1. Push this repository to GitHub.
2. Go to [render.com](https://render.com) → **New Web Service** → connect the repo.
3. Render auto-detects `render.yaml` and configures the service as a **Docker**
   service (see `Dockerfile`).
4. A unique `SESSION_SECRET` is generated automatically.
5. Deploy.

**Why Docker, not Render's native Python runtime:** ML-KEM (via `liboqs-python`)
builds the real `liboqs` C library itself the first time the app imports `oqs` --
that build needs `cmake` and a C compiler. Render's native Python runtime image
doesn't include `cmake`, so a first deploy on that runtime fails with
`cmake: not found`. The `Dockerfile` installs the real build toolchain
(`cmake`, `build-essential`, `ninja-build`, `git`) and forces the liboqs build
to happen once at image-build time -- for all three parameter sets the app
actually uses (ML-KEM-512/768/1024) -- instead of on every container start.
See `CHANGES.md` for the incident writeup.

**Free-tier note:** Render free services sleep after 15 minutes of inactivity.
The first request after a sleep cycle takes ~30–50 seconds to respond (cold start).
**Visit the deployed URL a few minutes before any live demo or defence** to ensure
the service is awake.

**Database note:** Render's free tier uses an ephemeral filesystem -- the SQLite
database is recreated on every deploy or restart. `seed.py` runs on startup and
re-creates all demo accounts automatically, so the demo is always ready.

### Adding a TURN server (optional -- for restrictive networks)

WebRTC calls use Google's public STUN server (`stun:stun.l.google.com:19302`) which
works on most networks. If calls fail behind a strict corporate firewall or symmetric
NAT, add a free TURN server:

1. Create a free account at [Metered.ca](https://www.metered.ca/tools/openrelay/).
2. Add your TURN credentials to `ICE_SERVERS` in `app/static/js/call.js`.

---

## Real ML-KEM implementation (via liboqs)

An earlier build used `MockKyber`, a SHA-256-based placeholder with the same
interface as a real KEM but no lattice cryptography and no quantum resistance.
That has been replaced with `KyberKEM` in `app/crypto/hybrid_fusion.py`, a thin
wrapper around `oqs.KeyEncapsulation(...)` from `liboqs-python` (Open Quantum
Safe's `liboqs`, NIST FIPS 203). See `CHANGES.md` for the full history of that
fix, the byte-truncation flaw a peer reviewer separately caught and fixed, and
the later change described below.

Each of the three profiles now selects a different real ML-KEM parameter set
rather than all defaulting to the same one:

| Profile | Operation | ML-KEM parameter set |
|---|---|---|
| SPEED_PROFILE | video_call | ML-KEM-512 |
| BALANCED_PROFILE | chat | ML-KEM-768 |
| SECURITY_PROFILE | patient_record | ML-KEM-1024 |

The "traditional" comparison baseline stays fixed on ML-KEM-768 for a fair,
apples-to-apples benchmark. See `CHANGES.md` section 6 for the reasoning,
the literature check behind it, and the real re-benchmark numbers.

**First run note:** `liboqs-python` builds the underlying `liboqs` C library
from source the first time it's imported (needs `cmake`, `git`, and a C
compiler -- see that library's own install docs if this fails). That build can
take several minutes and will make the first request to any page that touches
crypto (login, `/crypto-lab`, `/call`, `/records`, `/chat`) feel slow or
briefly unresponsive; it only happens once per environment.

---

*Anchor University Lagos · Department of Computer Science · 2025–2026*
# Telemedicine_secure_system
