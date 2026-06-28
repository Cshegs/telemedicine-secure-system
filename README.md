# TeleMedSecure — Hybrid ECC–Kyber Telemedicine Platform

**Final-year Computer Science project · Anchor University Lagos**

Research paper: *"Design of a Context-Aware Hybrid ECC–Kyber Cryptographic Framework
with Secure Key Fusion for Telemedicine Information Security."*

---

## What this system demonstrates

The paper's central contribution is a **six-step hybrid key fusion pipeline** that
blends classical ECC (X25519) with post-quantum Kyber via controllable α/β weights:

```
Step 1: ECC X25519 key exchange          → K1
Step 2: CRYSTALS-Kyber key encapsulation → K2
Step 3: SHA-256 normalisation            → K1', K2'
Step 4: Weighted fusion                  → Kf = SHA256(α·K1' ‖ β·K2')
Step 5: HKDF context derivation          → Kfinal = HKDF(Kf ‖ SID ‖ T ‖ PID)
Step 6: AES-256-GCM encryption           → C
```

Different telemedicine functions use different weighting profiles:

| Feature | Profile | α (ECC) | β (Kyber) | Rationale |
|---|---|---|---|---|
| Video call session | SPEED_PROFILE | 0.7 | 0.3 | Live calls cannot tolerate slow key setup |
| Secure chat | BALANCED_PROFILE | 0.4 | 0.6 | Paper's recommended optimal operating point |
| Patient records | SECURITY_PROFILE | 0.2 | 0.8 | Long-lived data must resist future quantum attacks |

**Every real user action (sending a message, saving a record, starting a call) runs
the pipeline live and logs the result** — making the paper's Table I a continuously
demonstrable feature of the running system.

---

## Honest scope: what is and isn't encrypted by the hybrid framework

- **Patient records** — encrypted end-to-end with `Kfinal` via AES-256-GCM. ✓
- **Chat messages** — each message encrypted with a fresh `Kfinal`. ✓
- **Video/audio streams** — encrypted natively by WebRTC (DTLS-SRTP), which is
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

Open **http://localhost:8000** — demo credentials are shown on the login page.

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
| `/chat` | Real-time WebSocket chat — each message encrypted with BALANCED_PROFILE |
| `/call` | WebRTC video call — SPEED_PROFILE pipeline runs before WebRTC handshake |
| `/crypto-lab` | **Crypto Transparency Dashboard** — live log, Chart.js comparison chart, pipeline step visualiser, "Run Live Comparison" button |
| `/crypto-test` | Quick manual pipeline test — fire any profile and inspect raw JSON output |

---

## Crypto Lab (for examiners)

The **Crypto Lab** (`/crypto-lab`) is the core examiner-facing feature. It shows:

1. **Live operation log** — every call to `establish_session_key()` (triggered by real
   user actions) appears here with operation type, α/β weights, K1′/K2′/Kf previews,
   and execution time.
2. **Comparison chart** — Chart.js bar chart of average execution time per profile,
   built from actual logged history — the live version of Table I from the paper.
3. **"Run Live Comparison" button** — fires all three profiles back-to-back and shows
   timing side-by-side in real time. Click this during a defence to demonstrate the
   speed/security trade-off on demand.
4. **Pipeline step visualiser** — shows Steps 1–6 for the most recent operation with
   hex previews at each step (K1′, K2′, Kf, SID).

---

## Deployment (Render.com free tier)

1. Push this repository to GitHub.
2. Go to [render.com](https://render.com) → **New Web Service** → connect the repo.
3. Render auto-detects `render.yaml` and configures the service.
4. A unique `SESSION_SECRET` is generated automatically.
5. Deploy.

**Free-tier note:** Render free services sleep after 15 minutes of inactivity.
The first request after a sleep cycle takes ~30–50 seconds to respond (cold start).
**Visit the deployed URL a few minutes before any live demo or defence** to ensure
the service is awake.

**Database note:** Render's free tier uses an ephemeral filesystem — the SQLite
database is recreated on every deploy or restart. `seed.py` runs on startup and
re-creates all demo accounts automatically, so the demo is always ready.

### Adding a TURN server (optional — for restrictive networks)

WebRTC calls use Google's public STUN server (`stun:stun.l.google.com:19302`) which
works on most networks. If calls fail behind a strict corporate firewall or symmetric
NAT, add a free TURN server:

1. Create a free account at [Metered.ca](https://www.metered.ca/tools/openrelay/).
2. Add your TURN credentials to `ICE_SERVERS` in `app/static/js/call.js`.

---

## Swapping MockKyber for real ML-KEM-768

The current build uses `MockKyber` (SHA-256 based placeholder) so the platform runs
without native compiled dependencies. To use real CRYSTALS-Kyber:

```bash
pip install liboqs-python
```

Then in `app/crypto/hybrid_fusion.py`, replace `MockKyber` with:

```python
import oqs

class RealKyber:
    def KeyGen(self):
        kem = oqs.KeyEncapsulation("Kyber768")
        pk = kem.generate_keypair()
        return pk, kem.export_secret_key()

    def Encaps(self, pk):
        kem = oqs.KeyEncapsulation("Kyber768")
        ct, ss = kem.encap_secret(pk)
        return ct, ss

    def Decaps(self, ciphertext, sk):
        kem = oqs.KeyEncapsulation("Kyber768", secret_key=sk)
        return kem.decap_secret(ciphertext)
```

The rest of the six-step pipeline (Steps 3–6) is unchanged.

---

*Anchor University Lagos · Department of Computer Science · 2025–2026*
# Telemedicine_secure_system
