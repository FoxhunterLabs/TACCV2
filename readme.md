# TACCV2 — Co‑Presence Pairing System

TACCV2 is a **research / prototype** co‑presence pairing system that derives a short‑term shared secret from **simultaneous physical motion** (IMU data) and uses it to authenticate a real cryptographic handshake.

The relay server is intentionally *dumb*: it never derives secrets, never sees raw sensor data, and only forwards messages.

This system is designed to be **inspectable, conservative, and safety‑biased** rather than maximally aggressive in entropy extraction.

---

## What TACCV2 Is

* A **co‑presence bootstrap**: two devices that are physically together can pair without pre‑shared keys or PKI.
* A **hybrid system**: physical signal agreement → conservative entropy handling → standard cryptography.
* A **real protocol**: interactive reconciliation, transcript binding, authenticated key exchange.

## What TACCV2 Is *Not*

* ❌ A replacement for standard key agreement
* ❌ A claim of provable IMU min‑entropy
* ❌ A fully hardened solution against active physical injection

You still need:

* UX confirmation (e.g. SAS comparison)
* Multi‑sensor redundancy
* Time‑bounded challenge windows

---

## High‑Level Architecture

### Server (Relay)

* FastAPI + WebSocket
* Forwards packets between Alice and Bob
* Never derives keys
* Never processes sensor data
* Session‑scoped, time‑limited

### Clients

Reference client implementation is included.

Each client performs:

1. IMU sampling (accelerometer + optional gyroscope)
2. Signal preprocessing (resample → high‑pass filter)
3. Quantization with **erasures** (guard band)
4. Mask exchange → intersection of confident samples
5. Interactive **Cascade‑style reconciliation** with backtracking
6. Explicit leakage accounting
7. Conservative entropy clamp
8. Privacy amplification (HKDF) → pairing secret **Kp**
9. **Kp‑authenticated X25519 handshake**
10. Session keys via HKDF → ChaCha20‑Poly1305

---

## Cryptographic Flow

```
IMU motion
   ↓
Quantized bits (with erasures)
   ↓
Mask intersection
   ↓
Cascade reconciliation (interactive)
   ↓
Leakage accounting + entropy clamp
   ↓
HKDF → pairing secret Kp (≥128 bits required)
   ↓
Commit(Kp)
   ↓
X25519 + PSK‑bound transcript
   ↓
Session send/recv keys
```

Key properties:

* Reconciliation transcript is **hashed and bound** into Kp derivation
* Commitments prevent downgrade / mismatch before handshake
* Handshake authentication is Noise‑like and transcript‑bound

---

## Entropy Philosophy (Important)

TACCV2 **does not claim provable min‑entropy** from IMU data.

Instead it uses:

* Fast randomness *gates* (bias, runs, autocorrelation)
* A **heuristic entropy bound** (bias + most‑common‑byte)
* A hard **per‑bit entropy cap** (default: 0.20 bits)
* Explicit subtraction of reconciliation leakage
* A large fixed safety margin

If ≥128 bits of conservative entropy cannot be justified, pairing **aborts**.

This is intentional.

---

## Dependencies

### Server

```bash
pip install fastapi uvicorn pydantic pycryptodome
```

### Client

```bash
pip install websockets cryptography
```

---

## Running the Relay Server

```bash
uvicorn app:app --host 0.0.0.0 --port 8000
```

Create a session:

```bash
curl -X POST http://localhost:8000/session
```

---

## Running Clients (Two Terminals)

```bash
python app.py client --role alice --session CODE --samples alice.json
python app.py client --role bob   --session CODE --samples bob.json
```

Each `samples.json` file contains timestamped IMU samples.

---

## Local Demo (No Network)

Runs a simulated two‑party reconciliation with injected bit errors:

```bash
python app.py demo_local --ber 0.15
```

Demonstrates:

* Cascade backtracking
* Leakage accounting
* Entropy clamping
* Kp derivation

---

## Threat Model (Explicit)

Designed to resist:

* Passive network adversaries
* Relay compromise
* Accidental mis‑pairing

**Not fully resistant** to:

* Active physical signal injection
* Sophisticated sensor spoofing
* High‑energy mechanical coupling attacks

Mitigations are expected at the system level (UX + sensors + policy).

---

## Status

* Research / prototype quality
* Not audited
* Not production‑ready

Intended for:

* Experimentation
* Security research
* Co‑presence / human‑in‑the‑loop systems

---

## License / Use

No warranty. No security guarantees.

Use for learning, research, and inspection.

If you deploy this in production without review, that’s on you.
