#!/usr/bin/env python3
"""
TACCV2 — Co-Presence Pairing System (Relay + Reference Clients)

A "real system" architecture (still research/prototype):

Server
- Dumb relay (FastAPI WebSocket). Server never derives secrets.

Clients (reference implementation included in this file)
- Co-presence key bootstrap:
  1) IMU sampling (accel + optional gyro) -> combined magnitude.
  2) Preprocess (resample -> high-pass).
  3) Quantize with ERASURES (guard band): produces aligned per-sample bits with None slots.
  4) Exchange erasure masks; take intersection to keep only mutually-confident positions (alignment preserved).
  5) Interactive Cascade-like reconciliation (Bob queries Alice parities) with backtracking.
  6) Leakage accounting + conservative entropy clamp.
  7) Privacy amplification (HKDF) => pairing secret Kp.
  8) Kp authenticates a real X25519 handshake -> session keys (send/recv).
  9) Use session keys with ChaCha20-Poly1305.

What this is NOT
- A replacement for standard key agreement; it is a co-presence bootstrap.
- Fully bulletproof vs active physical injection; you still need UX + multi-sensor + challenge windows.

Dependencies (server):
  pip install fastapi uvicorn pydantic pycryptodome

Dependencies (client modes):
  pip install websockets cryptography

Run relay:
  uvicorn app:app --host 0.0.0.0 --port 8000

Create session:
  curl -X POST http://localhost:8000/session

Run two clients (two terminals):
  python app.py client --role alice --session CODE --samples alice.json
  python app.py client --role bob   --session CODE --samples bob.json

Local demo (no relay):
  python app.py demo_local --ber 0.15
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import hmac
import json
import math
import random
import secrets
import statistics
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Literal

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from Crypto.Cipher import ChaCha20_Poly1305


# ============================================================
# Protocol constants
# ============================================================

PROTO_NAME = "TACCV2"
PROTO_VER = 4

ROLE = Literal["alice", "bob"]

MSG_TYPES = {
    "hello",
    "peer_joined",
    "peer_left",
    "relay",
    "error",
    "ping", "pong",
    "packet",
    "commit",
}

SESSION_TTL_S = 30 * 60
SESSION_SWEEP_S = 60


# ============================================================
# Common crypto helpers
# ============================================================

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """
    Minimal HKDF-SHA256 (RFC5869 style).
    """
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]

def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()

def pack_bits(bits: List[int]) -> bytes:
    """
    Pack bits into bytes (big-endian per byte). Truncates to multiple of 8.
    """
    m = (len(bits) // 8) * 8
    out = bytearray()
    for i in range(0, m, 8):
        v = 0
        for j in range(8):
            v = (v << 1) | (bits[i + j] & 1)
        out.append(v)
    return bytes(out)

def unpack_bits(buf: bytes, n_bits: int) -> List[int]:
    out: List[int] = []
    for b in buf:
        for i in range(7, -1, -1):
            out.append((b >> i) & 1)
            if len(out) >= n_bits:
                return out
    return out

def pack_mask(mask: List[bool]) -> bytes:
    return pack_bits([1 if m else 0 for m in mask])

def unpack_mask(buf: bytes, n_bits: int) -> List[bool]:
    return [bool(x) for x in unpack_bits(buf, n_bits=n_bits)]

def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> Dict[str, str]:
    nonce = secrets.token_bytes(12)
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    if aad:
        cipher.update(aad)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    blob = nonce + ct + tag
    return {"blob_b64": base64.b64encode(blob).decode()}

def aead_decrypt(key: bytes, blob_b64: str, aad: bytes = b"") -> bytes:
    blob = base64.b64decode(blob_b64)
    if len(blob) < 12 + 16:
        raise ValueError("blob too short")
    nonce = blob[:12]
    tag = blob[-16:]
    ct = blob[12:-16]
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    if aad:
        cipher.update(aad)
    return cipher.decrypt_and_verify(ct, tag)


# ============================================================
# IMU sample + preprocessing
# ============================================================

@dataclass(frozen=True)
class IMUSample:
    t: float
    ax: float
    ay: float
    az: float
    gx: Optional[float] = None
    gy: Optional[float] = None
    gz: Optional[float] = None

def _mag3(x: float, y: float, z: float) -> float:
    return math.sqrt(x*x + y*y + z*z)

def combined_signal(s: IMUSample, gyro_weight: float = 0.25) -> float:
    acc = _mag3(s.ax, s.ay, s.az)
    if s.gx is None or s.gy is None or s.gz is None:
        return acc
    gyro = _mag3(s.gx, s.gy, s.gz)
    return acc + gyro_weight * gyro

def resample_linear(samples: List[IMUSample], rate_hz: float, duration_s: float, gyro_weight: float) -> List[float]:
    """
    Resample combined magnitude to a uniform time grid using linear interpolation.
    """
    if not samples:
        raise ValueError("no samples")
    samples = sorted(samples, key=lambda x: x.t)
    t0 = samples[0].t
    t1 = t0 + duration_s
    step = 1.0 / rate_hz

    ts = [s.t for s in samples]
    xs = [combined_signal(s, gyro_weight=gyro_weight) for s in samples]

    def interp(t: float) -> float:
        if t <= ts[0]:
            return xs[0]
        if t >= ts[-1]:
            return xs[-1]
        i = 0
        while i < len(ts) and ts[i] < t:
            i += 1
        tL, tR = ts[i-1], ts[i]
        xL, xR = xs[i-1], xs[i]
        if tR == tL:
            return xL
        u = (t - tL) / (tR - tL)
        return xL + u * (xR - xL)

    out = []
    t = t0
    while t < t1:
        out.append(interp(t))
        t += step
    return out

def moving_average(x: List[float], k: int) -> List[float]:
    if k <= 1:
        return x[:]
    out = []
    s = 0.0
    q: List[float] = []
    for v in x:
        q.append(v)
        s += v
        if len(q) > k:
            s -= q.pop(0)
        out.append(s / len(q))
    return out

def highpass(x: List[float], k: int) -> List[float]:
    ma = moving_average(x, k)
    return [a - b for a, b in zip(x, ma)]

def quality_metrics(x_hp: List[float]) -> Dict[str, Any]:
    """
    Cheap gates for "not enough motion" / "too smooth".
    """
    if len(x_hp) < 64:
        return {"ok": False, "reason": "too_few_samples", "n": len(x_hp)}
    stdev = statistics.pstdev(x_hp) if len(x_hp) > 1 else 0.0
    diffs = [x_hp[i+1]-x_hp[i] for i in range(len(x_hp)-1)]
    diff_stdev = statistics.pstdev(diffs) if len(diffs) > 1 else 0.0
    ratio = diff_stdev / stdev if stdev > 1e-12 else 0.0
    flags = []
    if stdev < 1e-3:
        flags.append("low_variance")
    if ratio < 0.30:
        flags.append("too_smooth_or_periodic")
    return {
        "ok": "low_variance" not in flags,
        "n": len(x_hp),
        "stdev": stdev,
        "diff_ratio": ratio,
        "flags": flags,
    }


# ============================================================
# Quantization with erasures (guard band)
# ============================================================

def quantize_sign_guard(
    x_hp: List[float],
    guard_sigma: float = 0.35,
    include_diff_bit: bool = True,
) -> Tuple[List[Optional[int]], List[bool], Dict[str, Any]]:
    """
    Output aligned per-sample bits with erasures:
      bit[i] in {0,1,None} and mask[i] = (bit[i] is not None).

    Primary bit is sign(x_hp[i]) with threshold tau = guard_sigma * stdev(x_hp).
    Optional second bit from sign(diff).
    """
    if len(x_hp) < 2:
        raise ValueError("need at least 2 samples")

    stdev = statistics.pstdev(x_hp) if len(x_hp) > 1 else 0.0
    tau = guard_sigma * stdev

    def q(v: float) -> Optional[int]:
        if v > tau:
            return 1
        if v < -tau:
            return 0
        return None

    bits: List[Optional[int]] = []
    mask: List[bool] = []
    for i, v in enumerate(x_hp):
        b = q(v)
        bits.append(b)
        mask.append(b is not None)

        if include_diff_bit:
            db = None if i == 0 else q(v - x_hp[i-1])
            bits.append(db)
            mask.append(db is not None)

    dbg = {
        "guard_sigma": guard_sigma,
        "tau": tau,
        "include_diff_bit": include_diff_bit,
        "aligned_len": len(bits),
        "kept": sum(1 for m in mask if m),
        "dropped": sum(1 for m in mask if not m),
    }
    return bits, mask, dbg

def intersect_and_extract(
    bits_self: List[Optional[int]], mask_self: List[bool],
    mask_peer: List[bool],
) -> Tuple[List[int], Dict[str, Any]]:
    if len(bits_self) != len(mask_self) or len(mask_self) != len(mask_peer):
        raise ValueError("mask/bit length mismatch (alignment failed)")
    inter = [a and b for a, b in zip(mask_self, mask_peer)]
    out: List[int] = []
    for i, keep in enumerate(inter):
        if not keep:
            continue
        v = bits_self[i]
        if v is None:
            continue
        out.append(int(v))
    dbg = {
        "aligned_len": len(inter),
        "kept_positions": sum(1 for k in inter if k),
        "out_bit_len": len(out),
        "mask_len": len(mask_self),
        "mask_budget_bits": 0,  # not modeled; compensated via safety_margin_bits
        "mask_budget_note": "mask side-info not modeled as bits"
    }
    return out, dbg


# ============================================================
# Randomness & entropy (heuristics)
# ============================================================


def quick_randomness_checks(bits: List[int]) -> Dict[str, Any]:
    """
    Fast *quality gates* on the reconciled bitstream.

    These checks do NOT prove security. They are abuse-prevention:
      - Abort on too few bits (can't possibly have enough entropy).
      - Abort on strong bias / pathological runs.
      - Abort on strong short-lag autocorrelation (lags 1..8).
    """
    n = len(bits)
    if n < 2048:
        return {"ok": False, "reason": "too_few_bits", "n": n}

    ones = sum(bits)
    p1 = ones / n
    freq_ok = abs(p1 - 0.5) < 0.10

    # runs test (very rough)
    runs = 1
    for i in range(1, n):
        if bits[i] != bits[i - 1]:
            runs += 1
    exp_runs = 2 * n * p1 * (1 - p1) + 1
    runs_ok = abs(runs - exp_runs) < 0.25 * exp_runs

    def corr(lag: int) -> float:
        m = n - lag
        if m <= 0:
            return 0.0
        eq = sum(1 for i in range(m) if bits[i] == bits[i + lag])
        return (eq / m - 0.5) * 2.0

    corrs = {f"corr{lag}": corr(lag) for lag in range(1, 9)}
    corr_ok = all(abs(corrs[f"corr{lag}"]) < 0.25 for lag in range(1, 9))

    ok = freq_ok and runs_ok and corr_ok
    out = {"ok": ok, "n": n, "p1": p1, "runs": runs, "exp_runs": exp_runs,
           "freq_ok": freq_ok, "runs_ok": runs_ok, "corr_ok": corr_ok}
    out.update(corrs)
    return out


def heuristic_entropy_bound_bits(bits: List[int], per_bit_cap: float = 0.20) -> float:
    """
    Conservative *heuristic entropy bound* (bits).

    This is NOT defensible "min-entropy" and must not be presented as such.
    It is an internal safety heuristic intended to prevent over-extraction.

    We compute two crude per-bit estimates and take the minimum, then clamp:
      - bias-based bound (from marginal p(1))
      - most-common-byte bound (catches some correlations)
      - final clamp per bit: `per_bit_cap` (e.g., 0.20 => assume <=0.2 bits of entropy per kept bit)
    """
    n = len(bits)
    if n < 2048:
        return 0.0
    ones = sum(bits)
    p1 = ones / n
    p0 = 1.0 - p1
    per_bit_bias = -math.log2(max(p0, p1))

    b = pack_bits(bits)
    if len(b) < 64:
        return 0.0
    freq: Dict[int, int] = {}
    for x in b:
        freq[x] = freq.get(x, 0) + 1
    mcv = max(freq.values())
    per_byte = -math.log2(mcv / len(b))
    per_bit_bytes = per_byte / 8.0

    per_bit = min(per_bit_bias, per_bit_bytes)
    per_bit = min(per_bit, per_bit_cap)
    return per_bit * n


# ============================================================
# Cascade reconciliation (interactive, backtracking)
# ============================================================

def parity(bits: List[int]) -> int:
    p = 0
    for b in bits:
        p ^= (b & 1)
    return p

def make_permutation(n: int, seed: bytes) -> List[int]:
    rng = random.Random(int.from_bytes(sha256(seed), "big"))
    idx = list(range(n))
    rng.shuffle(idx)
    return idx

def invert_perm(perm: List[int]) -> List[int]:
    inv = [0] * len(perm)
    for j, i in enumerate(perm):
        inv[i] = j
    return inv

@dataclass
class RoundCtx:
    r: int
    block_size: int
    perm_seed: bytes
    perm: List[int]   # perm_index -> original_index
    inv: List[int]    # original_index -> perm_index
    alice_parities: Optional[List[int]] = None

def build_rounds(n_bits: int, rounds: int, initial_block: int, seed: bytes) -> List[RoundCtx]:
    out: List[RoundCtx] = []
    block = initial_block
    for r in range(rounds):
        perm_seed = sha256(seed + r.to_bytes(2, "big"))
        perm = make_permutation(n_bits, perm_seed)
        inv = invert_perm(perm)
        out.append(RoundCtx(r=r, block_size=min(block, n_bits), perm_seed=perm_seed, perm=perm, inv=inv))
        block = min(n_bits, block * 2)
    return out

class AliceParityOracle:
    """
    Alice-side oracle (local) supporting parity list and range parity.
    """
    def __init__(self, a_bits: List[int], rounds: List[RoundCtx]):
        self.rounds = rounds
        self._prefix: Dict[int, List[int]] = {}
        self._a_perm: Dict[int, List[int]] = {}
        for rc in rounds:
            a_perm = [a_bits[i] for i in rc.perm]
            self._a_perm[rc.r] = a_perm
            pref = [0]
            p = 0
            for b in a_perm:
                p ^= (b & 1)
                pref.append(p)
            self._prefix[rc.r] = pref

    def parity_list(self, r: int) -> List[int]:
        rc = self.rounds[r]
        a_perm = self._a_perm[r]
        out = []
        for off in range(0, len(a_perm), rc.block_size):
            out.append(parity(a_perm[off: off + rc.block_size]))
        return out

    def range_parity(self, r: int, lo: int, hi: int) -> int:
        pref = self._prefix[r]
        lo = max(0, min(lo, len(pref)-1))
        hi = max(0, min(hi, len(pref)-1))
        if hi < lo:
            lo, hi = hi, lo
        return pref[hi] ^ pref[lo]

class BobCascadeReconciler:
    """
    Bob corrects his bits toward Alice using interactive parity queries.

    Leakage accounting:
      - block parity lists: 1 bit per block parity from Alice
      - range parity answers: 1 bit per answer

    NOTE: Still a prototype, but it is a real interactive protocol (not "drop blocks").
    """
    def __init__(self, b_bits: List[int], rounds: List[RoundCtx], oracle: Any):
        self.b = b_bits[:]
        self.rounds = rounds
        self.oracle = oracle
        self.leakage = 0
        self.flips = 0
        self.block_parity_bits = 0
        self.range_query_bits = 0

    def _bob_perm_bits(self, rc: RoundCtx) -> List[int]:
        return [self.b[i] for i in rc.perm]

    async def reconcile(self) -> Tuple[List[int], Dict[str, Any]]:
        n = len(self.b)
        queues: List[List[int]] = [[] for _ in self.rounds]
        inq: List[set] = [set() for _ in self.rounds]

        # Fetch Alice parity lists and seed queues
        for rc in self.rounds:
            alice_par = await self.oracle.parity_list(rc.r)
            rc.alice_parities = alice_par
            self.leakage += len(alice_par)
            self.block_parity_bits += len(alice_par)

            b_perm = self._bob_perm_bits(rc)
            bob_par = []
            for off in range(0, len(b_perm), rc.block_size):
                bob_par.append(parity(b_perm[off: off + rc.block_size]))

            for bi, (pa, pb) in enumerate(zip(alice_par, bob_par)):
                if pa != pb:
                    queues[rc.r].append(bi)
                    inq[rc.r].add(bi)

        async def correct_block(rc: RoundCtx, bi: int):
            # Re-check mismatch in current state
            a_par = rc.alice_parities[bi] if rc.alice_parities is not None else None
            if a_par is None:
                return
            b_perm = self._bob_perm_bits(rc)
            lo = bi * rc.block_size
            hi = min(lo + rc.block_size, len(b_perm))
            if parity(b_perm[lo:hi]) == a_par:
                return

            # binary search
            l, h = lo, hi
            while h - l > 1:
                mid = (l + h) // 2
                pa = await self.oracle.range_parity(rc.r, l, mid)
                self.leakage += 1
                self.range_query_bits += 1
                pb = parity(b_perm[l:mid])
                if pa != pb:
                    h = mid
                else:
                    l = mid

            # flip
            orig = rc.perm[l]
            self.b[orig] ^= 1
            self.flips += 1

            # backtrack to earlier rounds
            for prev in self.rounds[:rc.r]:
                prev_bi = prev.inv[orig] // prev.block_size
                if prev_bi not in inq[prev.r]:
                    queues[prev.r].append(prev_bi)
                    inq[prev.r].add(prev_bi)

        # process queues until stable
        progressed = True
        while progressed:
            progressed = False
            for rc in self.rounds:
                q = queues[rc.r]
                while q:
                    bi = q.pop(0)
                    inq[rc.r].discard(bi)
                    before = self.flips
                    await correct_block(rc, bi)
                    if self.flips != before:
                        progressed = True

        stats = {
            "n_bits": n,
            "rounds": len(self.rounds),
            "flips": self.flips,
            "leakage_bits": self.leakage,
            "block_parity_bits": self.block_parity_bits,
            "range_query_bits": self.range_query_bits,
        }
        return self.b[:], stats


# ============================================================
# Pairing secret (Kp) derivation with clamp
# ============================================================


def derive_kp(
    reconciled_bits: List[int],
    session_id: bytes,
    leakage_bits: int,
    recon_transcript_hash: bytes,
    desired_bytes: int = 16,
    safety_margin_bits: int = 512,
    per_bit_cap: float = 0.20,
) -> Tuple[bytes, Dict[str, Any]]:
    """
    Derive pairing secret Kp via HKDF with aggressive clamps.

    - `heuristic_entropy_bound_bits` is a conservative heuristic bound (NOT true min-entropy).
    - We subtract `leakage_bits` and a chunky safety margin.
    - Abort if we can't justify at least 128-bit Kp.

    `recon_transcript_hash` binds Kp derivation to the exact reconciliation transcript.
    """
    gates = quick_randomness_checks(reconciled_bits)
    if not gates["ok"]:
        raise ValueError(f"randomness gates failed: {gates}")

    est = heuristic_entropy_bound_bits(reconciled_bits, per_bit_cap=per_bit_cap)
    usable = max(0.0, est - leakage_bits - safety_margin_bits)
    max_bytes = int(usable // 8)
    out_len = min(desired_bytes, max_bytes)

    if out_len < 16:
        raise ValueError(
            "Insufficient conservative entropy bound to safely output 128-bit Kp. "
            f"est≈{est:.1f} bits, leakage≈{leakage_bits}, safety_margin={safety_margin_bits}, "
            f"usable≈{usable:.1f} bits, max_bytes={max_bytes}"
        )

    material = pack_bits(reconciled_bits)
    salt = sha256(b"TACCV2-KP-SALT" + session_id)
    info = b"TACCV2|kp|v4|" + recon_transcript_hash
    kp = hkdf_sha256(material, salt=salt, info=info, length=out_len)

    dbg = {
        "gates": gates,
        "heuristic_entropy_bound_bits": est,
        "per_bit_cap": per_bit_cap,
        "leakage_bits": leakage_bits,
        "safety_margin_bits": safety_margin_bits,
        "usable_bits_est": usable,
        "max_bytes": max_bytes,
        "kp_len_bytes": out_len,
        "recon_transcript_hash_hex": recon_transcript_hash.hex(),
        "kp_fingerprint": hashlib.sha256(kp).hexdigest()[:16],
    }
    return kp, dbg



def kp_commit(kp: bytes, session_id: bytes, recon_transcript_hash: bytes) -> bytes:
    return sha256(b"TACCV2|commit|v2|" + kp + session_id + recon_transcript_hash)


def sas6(kp: bytes, session_id: bytes) -> str:
    v = int.from_bytes(sha256(b"TACCV2|sas|" + kp + session_id)[:4], "big") % 1_000_000
    return f"{v:06d}"


# ============================================================
# X25519 + PSK handshake (real X25519, Noise-like confirmation)
# ============================================================

def _require_cryptography():
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        return X25519PrivateKey, X25519PublicKey, Encoding, PublicFormat
    except Exception as e:
        raise RuntimeError("cryptography not installed. Run: pip install cryptography") from e


@dataclass
class HandshakeState:
    role: str
    session_id: bytes
    kp: bytes
    recon_transcript_hash: bytes
    alice_commit: bytes
    bob_commit: bytes
    my_priv: Any
    my_pub_raw: bytes
    my_nonce: bytes
    peer_pub_raw: Optional[bytes] = None
    peer_nonce: Optional[bytes] = None
    transcript: bytes = b""
    master: Optional[bytes] = None


def hs_init(role: str, session_id: bytes, kp: bytes, recon_transcript_hash: bytes, alice_commit: bytes, bob_commit: bytes) -> HandshakeState:
    X25519PrivateKey, _, Encoding, PublicFormat = _require_cryptography()
    priv = X25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    nonce = secrets.token_bytes(16)
    return HandshakeState(
        role=role,
        session_id=session_id,
        kp=kp,
        recon_transcript_hash=recon_transcript_hash,
        alice_commit=alice_commit,
        bob_commit=bob_commit,
        my_priv=priv,
        my_pub_raw=pub,
        my_nonce=nonce,
    )


def hs_message_hello(st: HandshakeState) -> Dict[str, str]:
    return {"pub_b64": base64.b64encode(st.my_pub_raw).decode(), "nonce_b64": base64.b64encode(st.my_nonce).decode()}

def hs_receive_hello(st: HandshakeState, pub_raw: bytes, nonce: bytes) -> None:
    st.peer_pub_raw = pub_raw
    st.peer_nonce = nonce

def hs_derive_master(st: HandshakeState) -> bytes:
    if st.peer_pub_raw is None or st.peer_nonce is None:
        raise ValueError("missing peer hello")
    _, X25519PublicKey, _, _ = _require_cryptography()
    peer_pub = X25519PublicKey.from_public_bytes(st.peer_pub_raw)
    ss = st.my_priv.exchange(peer_pub)

    # deterministic transcript order: alice then bob
    if st.role == "alice":
        a_pub, a_nonce = st.my_pub_raw, st.my_nonce
        b_pub, b_nonce = st.peer_pub_raw, st.peer_nonce
    else:
        a_pub, a_nonce = st.peer_pub_raw, st.peer_nonce
        b_pub, b_nonce = st.my_pub_raw, st.my_nonce

    
    transcript = b"".join([
        b"TACCV2|hs|v4|",
        st.session_id,
        st.recon_transcript_hash,
        st.alice_commit,
        st.bob_commit,
        a_pub, a_nonce, b_pub, b_nonce,
    ])
    th = sha256(transcript)
    salt = sha256(b"TACCV2|psk|v4|" + st.kp + st.session_id + st.recon_transcript_hash + th)
    master = hkdf_sha256(ss, salt=salt, info=b"TACCV2|master|v4", length=32)
    st.transcript = transcript
    st.master = master
    return master

def hs_auth_tag(st: HandshakeState) -> bytes:
    if st.master is None:
        raise ValueError("master not derived")
    th = sha256(st.transcript)
    return hmac_sha256(st.master, b"TACCV2|auth|" + st.role.encode() + th)

def hs_verify_peer_tag(st: HandshakeState, peer_role: str, tag: bytes) -> bool:
    if st.master is None:
        raise ValueError("master not derived")
    th = sha256(st.transcript)
    exp = hmac_sha256(st.master, b"TACCV2|auth|" + peer_role.encode() + th)
    return hmac.compare_digest(exp, tag)

def hs_derive_session_keys(st: HandshakeState) -> Tuple[bytes, bytes]:
    if st.master is None:
        raise ValueError("master not derived")
    th = sha256(st.transcript)
    base = hkdf_sha256(st.master, salt=sha256(b"TACCV2|kdf|" + th), info=b"TACCV2|session|v4", length=64)
    k1, k2 = base[:32], base[32:]
    return (k1, k2) if st.role == "alice" else (k2, k1)


# ============================================================
# Relay server (FastAPI WebSocket)
# ============================================================

app = FastAPI(title="TACCV2 Relay", version=str(PROTO_VER))

class SessionCreateResp(BaseModel):
    session_code: str
    session_id_b64: str
    proto: str
    ver: int
    expires_in_s: int

class SessionInfoResp(BaseModel):
    session_code: str
    created_at: float
    expires_at: float
    present: Dict[str, bool]
    commits_present: Dict[str, bool]

_SESS: Dict[str, Dict[str, Any]] = {}
_LAST_SWEEP = 0.0

def _new_code() -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "".join(secrets.choice(alphabet) for _ in range(8))

def _now() -> float:
    return time.time()

def _sweep_expired():
    global _LAST_SWEEP
    now = _now()
    if now - _LAST_SWEEP < SESSION_SWEEP_S:
        return
    _LAST_SWEEP = now
    expired = [code for code, s in _SESS.items() if now >= s["expires_at"]]
    for code in expired:
        _SESS.pop(code, None)

def _require_session(code: str) -> Dict[str, Any]:
    _sweep_expired()
    if code not in _SESS:
        raise HTTPException(status_code=404, detail="unknown or expired session_code")
    return _SESS[code]

@app.post("/session", response_model=SessionCreateResp)
def create_session():
    _sweep_expired()
    code = _new_code()
    session_id = secrets.token_bytes(16)
    created_at = _now()
    expires_at = created_at + SESSION_TTL_S
    _SESS[code] = {
        "created_at": created_at,
        "expires_at": expires_at,
        "session_id": session_id,
        "ws": {"alice": None, "bob": None},
        "commit": {"alice": None, "bob": None},
    }
    return SessionCreateResp(
        session_code=code,
        session_id_b64=base64.b64encode(session_id).decode(),
        proto=PROTO_NAME,
        ver=PROTO_VER,
        expires_in_s=SESSION_TTL_S,
    )

@app.get("/session/{code}", response_model=SessionInfoResp)
def session_info(code: str):
    s = _require_session(code)
    present = {r: bool(s["ws"][r]) for r in ("alice", "bob")}
    commits_present = {r: bool(s["commit"][r]) for r in ("alice", "bob")}
    return SessionInfoResp(
        session_code=code,
        created_at=s["created_at"],
        expires_at=s["expires_at"],
        present=present,
        commits_present=commits_present,
    )

def _json_dumps(o: Any) -> str:
    return json.dumps(o, separators=(",", ":"), ensure_ascii=False)

async def _send(ws: WebSocket, msg_type: str, payload: Any = None):
    m: Dict[str, Any] = {"type": msg_type, "proto": PROTO_NAME, "ver": PROTO_VER}
    if payload is not None:
        m["payload"] = payload
    await ws.send_text(_json_dumps(m))

async def _relay(sess: Dict[str, Any], from_role: str, msg: Dict[str, Any]):
    to_role = "bob" if from_role == "alice" else "alice"
    peer = sess["ws"].get(to_role)
    if peer:
        await _send(peer, "relay", {"from": from_role, "msg": msg})

@app.websocket("/ws/{code}/{role}")
async def ws_pair(code: str, role: str, websocket: WebSocket):
    if role not in ("alice", "bob"):
        await websocket.accept()
        await _send(websocket, "error", {"error": "role must be alice|bob"})
        await websocket.close(code=1008)
        return

    sess = _require_session(code)
    await websocket.accept()

    # single connection per role
    old = sess["ws"].get(role)
    if old:
        try:
            await _send(old, "error", {"error": "another connection joined; disconnecting"})
            await old.close(code=1012)
        except Exception:
            pass

    sess["ws"][role] = websocket
    await _send(websocket, "hello", {
        "session_code": code,
        "role": role,
        "session_id_b64": base64.b64encode(sess["session_id"]).decode(),
        "expires_at": sess["expires_at"],
    })

    peer_role = "bob" if role == "alice" else "alice"
    peer_ws = sess["ws"].get(peer_role)
    if peer_ws:
        await _send(peer_ws, "peer_joined", {"role": role})

    try:
        while True:
            raw = await websocket.receive_text()
            try:
                msg = json.loads(raw)
                if not isinstance(msg, dict) or "type" not in msg:
                    raise ValueError("message must be JSON object with type")
                t = msg["type"]
                if t not in MSG_TYPES:
                    raise ValueError(f"unknown type: {t}")
            except Exception as e:
                await _send(websocket, "error", {"error": f"bad message: {e}"})
                continue

            if msg["type"] == "ping":
                await _send(websocket, "pong", {"t": _now()})
                continue

            if msg["type"] == "commit":
                payload = msg.get("payload", {})
                cb64 = payload.get("commit_b64")
                if not isinstance(cb64, str):
                    await _send(websocket, "error", {"error": "commit_b64 required"})
                    continue
                try:
                    c = base64.b64decode(cb64)
                except Exception:
                    await _send(websocket, "error", {"error": "invalid base64"})
                    continue
                if len(c) != 32:
                    await _send(websocket, "error", {"error": "commit must be 32 bytes"})
                    continue
                sess["commit"][role] = cb64
                await _relay(sess, role, msg)
                continue

            await _relay(sess, role, msg)

    except WebSocketDisconnect:
        pass
    finally:
        if sess["ws"].get(role) is websocket:
            sess["ws"][role] = None
        if peer_ws:
            try:
                await _send(peer_ws, "peer_left", {"role": role})
            except Exception:
                pass


# ============================================================
# Client reference implementation (WebSocket)
# ============================================================

class ClientConfig(BaseModel):
    rate_hz: float = Field(100.0, ge=10.0, le=500.0)
    duration_s: float = Field(10.0, ge=1.0, le=30.0)
    hp_window: int = Field(25, ge=1, le=200)
    gyro_weight: float = Field(0.25, ge=0.0, le=2.0)
    guard_sigma: float = Field(0.35, ge=0.0, le=2.0)
    include_diff_bit: bool = True
    cascade_rounds: int = Field(4, ge=1, le=8)
    initial_block: int = Field(32, ge=8, le=512)

def load_samples(path: str) -> List[IMUSample]:
    with open(path, "r", encoding="utf-8") as f:
        obj = json.load(f)
    arr = obj["samples"] if isinstance(obj, dict) and "samples" in obj else obj
    out: List[IMUSample] = []
    for s in arr:
        out.append(IMUSample(
            t=float(s["t"]),
            ax=float(s["ax"]),
            ay=float(s["ay"]),
            az=float(s["az"]),
            gx=float(s["gx"]) if "gx" in s and s["gx"] is not None else None,
            gy=float(s["gy"]) if "gy" in s and s["gy"] is not None else None,
            gz=float(s["gz"]) if "gz" in s and s["gz"] is not None else None,
        ))
    return out

def _require_websockets():
    try:
        import websockets
        return websockets
    except Exception as e:
        raise RuntimeError("websockets not installed. Run: pip install websockets") from e

class WSClient:
    """
    Reference client for Alice or Bob.

    Key design constraints:
      - Relay server is dumb: clients do all derivation.
      - Reconciliation transcript is hashed in a *role-canonical* way so BOTH sides
        derive the same recon_transcript_hash.
      - All recon-relevant packets carry a monotonically increasing sender-local `seq`.
    """

    def __init__(self, url: str, role: str, code: str, cfg: ClientConfig, samples: List[IMUSample]):
        self.url = url.rstrip("/")
        self.role = role
        self.peer_role = "bob" if role == "alice" else "alice"
        self.code = code
        self.cfg = cfg
        self.samples = samples

        self.ws = None
        self._recv_task: Optional[asyncio.Task] = None
        self.session_id: Optional[bytes] = None

        # aligned stream
        self.bits_opt: Optional[List[Optional[int]]] = None
        self.mask: Optional[List[bool]] = None

        # peer info
        self.peer_mask: Optional[List[bool]] = None
        self.peer_bitlen: Optional[int] = None
        self.peer_commit: Optional[bytes] = None

        # Per-sender recon transcript hashers (canonical across roles)
        self._recon_hasher_alice = hashlib.sha256()
        self._recon_hasher_bob = hashlib.sha256()

        # Monotonic outgoing seq (for ALL sent messages: packet + commit + handshake)
        self._seq_out = 0

        # Monotonic incoming seq from peer (anti-replay / duplicate suppression)
        self._peer_seq_in = 0

        # extracted bits
        self.bits: Optional[List[int]] = None
        self.n_agreed: Optional[int] = None

        # cascade service (alice)
        self._alice_oracle: Optional[AliceParityOracle] = None
        self._alice_rounds: Optional[List[RoundCtx]] = None

        # Kp + commit + handshake
        self.kp: Optional[bytes] = None
        self.commit: Optional[bytes] = None
        self.hs: Optional[HandshakeState] = None
        self.send_key: Optional[bytes] = None
        self.recv_key: Optional[bytes] = None

        # message dispatch
        self._pending: Dict[str, asyncio.Future] = {}
        self._peer_auth_tag: Optional[bytes] = None
        self._stashed_peer_hello: Optional[Tuple[bytes, bytes]] = None
        self.cascade_ready: bool = False
        self.cascade_leakage: Optional[int] = None

    # ------------------- transport -------------------

    async def connect(self):
        websockets = _require_websockets()
        ws_url = f"{self.url}/ws/{self.code}/{self.role}"
        self.ws = await websockets.connect(ws_url)

        # wait hello
        msg = await self._recv()
        if msg.get("type") != "hello":
            raise RuntimeError(f"expected hello, got {msg}")
        payload = msg["payload"]
        self.session_id = base64.b64decode(payload["session_id_b64"])

        self._recv_task = asyncio.create_task(self._recv_loop())

    async def _send(self, msg: Dict[str, Any]):
        assert self.ws is not None
        await self.ws.send(json.dumps(msg))

    async def _recv(self) -> Dict[str, Any]:
        assert self.ws is not None
        raw = await self.ws.recv()
        return json.loads(raw)

    async def _recv_loop(self):
        """
        Receive loop: handles server relay wrapper and routes peer messages.
        """
        while True:
            try:
                msg = await self._recv()
            except Exception:
                return

            t = msg.get("type")
            if t == "relay":
                wrapper = msg.get("payload", {}) or {}
                from_role = wrapper.get("from", self.peer_role)
                inner = wrapper.get("msg", {}) or {}
                await self._handle_peer(from_role, inner)
            elif t == "error":
                print(f"[{self.role}] server error: {msg.get('payload')}")
            # ignore other server messages

    # ------------------- recon transcript hashing -------------------

    def _is_recon_kind(self, kind: str) -> bool:
        """
        Recon transcript includes ONLY messages that influence the derived bit agreement:
          - mask exchange
          - bitlen agreement
          - cascade reconciliation (all cascade_* packets)
        It intentionally EXCLUDES commits and handshake packets to avoid circularity.
        """
        if kind in ("mask", "bitlen"):
            return True
        if kind.startswith("cascade_"):
            return True
        return False

    def _hash_recon_event(self, sender_role: str, payload: Dict[str, Any]) -> None:
        """
        Role-canonical transcript hashing.

        We keep *two* per-sender hashers (alice/bob). Every recon-relevant message updates
        the hasher for its sender role. Both sides will observe the same set of messages
        and thus compute the same recon_transcript_hash.

        Ordering:
          - Ordering across senders is NOT relied upon. Each per-sender stream is ordered
            by that sender's monotonically increasing `seq` (enforced by websocket order).
        """
        kind = str(payload.get("kind", ""))
        if not kind or not self._is_recon_kind(kind):
            return

        try:
            seq = int(payload.get("seq", 0) or 0)
        except Exception:
            seq = 0

        blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        h = sha256(blob)

        record = b"|".join([
            b"TACCV2", b"recon-msg", sender_role.encode("utf-8"),
            str(seq).encode("utf-8"), kind.encode("utf-8"),
            h,
        ])

        if sender_role == "alice":
            self._recon_hasher_alice.update(record)
        elif sender_role == "bob":
            self._recon_hasher_bob.update(record)
        else:
            self._recon_hasher_bob.update(record)

    def recon_transcript_hash(self) -> bytes:
        """
        Stable digest of reconciliation transcript (mask/bitlen/cascade_* only).
        """
        return sha256(
            b"TACCV2|recon|v1|"
            + self._recon_hasher_alice.digest()
            + self._recon_hasher_bob.digest()
        )

    # ------------------- request/notify helpers -------------------

    def _resolve(self, req_id: Optional[str], payload: Any):
        if req_id and req_id in self._pending:
            fut = self._pending.pop(req_id)
            if not fut.done():
                fut.set_result(payload)

    async def request(self, kind: str, payload: Dict[str, Any], timeout: float = 15.0) -> Any:
        """
        Send a request packet to peer and await the response carrying the same `id`.
        """
        req_id = secrets.token_hex(8)
        p = dict(payload)
        p["kind"] = kind
        p["id"] = req_id

        self._seq_out += 1
        p["seq"] = self._seq_out

        fut = asyncio.get_event_loop().create_future()
        self._pending[req_id] = fut

        self._hash_recon_event(self.role, p)

        await self._send({"type": "packet", "payload": p})
        return await asyncio.wait_for(fut, timeout=timeout)

    async def notify(self, kind: str, payload: Dict[str, Any]):
        """
        Send a one-way packet to peer. All packets get a monotonically increasing `seq`.
        """
        p = dict(payload)
        p["kind"] = kind

        self._seq_out += 1
        p["seq"] = self._seq_out

        self._hash_recon_event(self.role, p)

        await self._send({"type": "packet", "payload": p})

    # ------------------- inbound peer handling -------------------

    async def _handle_peer(self, from_role: str, msg: Dict[str, Any]):
        t = msg.get("type")

        # -------- commit channel --------
        if t == "commit":
            payload = msg.get("payload", {}) or {}

            seq_present = "seq" in payload
            seq = int(payload.get("seq", 0) or 0) if seq_present else 0
            if seq_present and seq and seq <= self._peer_seq_in:
                return
            if seq_present and seq:
                self._peer_seq_in = seq

            cb64 = payload.get("commit_b64")
            if cb64:
                self.peer_commit = base64.b64decode(cb64)
            return

        # -------- packets --------
        if t != "packet":
            return

        payload = msg.get("payload", {}) or {}
        kind = payload.get("kind")
        req_id = payload.get("id")

        # anti-replay / dup suppression on peer seq (only if present)
        seq_present = "seq" in payload
        if seq_present:
            try:
                seq = int(payload.get("seq", 0) or 0)
            except Exception:
                seq = 0
            if seq and seq <= self._peer_seq_in:
                return
            if seq:
                self._peer_seq_in = seq

        # hash recon transcript if recon message (sender is from_role)
        if isinstance(kind, str):
            self._hash_recon_event(from_role, payload)

        # --- mask exchange ---
        if kind == "mask":
            n = int(payload["n"])
            self.peer_mask = unpack_mask(base64.b64decode(payload["mask_b64"]), n_bits=n)
            return

        # --- bitlen exchange ---
        if kind == "bitlen":
            self.peer_bitlen = int(payload["n_bits"])
            return

        # --- cascade setup (alice) ---
        if kind == "cascade_setup":
            if self.role != "alice":
                return
            n = int(payload["n_bits"])
            rounds = int(payload["rounds"])
            initial_block = int(payload["initial_block"])
            seed = base64.b64decode(payload["seed_b64"])
            if self.bits is None or len(self.bits) < n:
                raise RuntimeError(
                    f"Alice bits too short for cascade_setup: have={0 if self.bits is None else len(self.bits)} need={n}"
                )
            a = self.bits[:n]
            rctx = build_rounds(n, rounds, initial_block, seed=seed)
            self._alice_rounds = rctx
            self._alice_oracle = AliceParityOracle(a, rctx)
            await self.notify("cascade_ready", {"n_bits": n})
            return

        # --- cascade parity list request (alice answers) ---
        if kind == "cascade_parity_list_req":
            if self.role != "alice":
                return
            r = int(payload["round"])
            if self._alice_oracle is None:
                raise RuntimeError("Alice has no oracle; did not receive cascade_setup")
            par = self._alice_oracle.parity_list(r)
            packed = pack_bits(par)
            await self.notify("cascade_parity_list", {
                "id": req_id,
                "round": r,
                "n_bits": len(par),
                "parities_b64": base64.b64encode(packed).decode(),
            })
            return

        # --- cascade range parity request (alice answers) ---
        if kind == "cascade_range_parity_req":
            if self.role != "alice":
                return
            r = int(payload["round"])
            lo = int(payload["lo"])
            hi = int(payload["hi"])
            if self._alice_oracle is None:
                raise RuntimeError("Alice has no oracle; did not receive cascade_setup")
            pbit = int(self._alice_oracle.range_parity(r, lo, hi))
            await self.notify("cascade_range_parity_resp", {"id": req_id, "round": r, "lo": lo, "hi": hi, "parity": pbit})
            return

        # --- cascade responses (bob resolves futures) ---
        if kind in ("cascade_parity_list", "cascade_range_parity_resp"):
            self._resolve(req_id, payload)
            return

        if kind == "cascade_ready":
            self.cascade_ready = True
            return

        if kind == "cascade_done":
            self.cascade_leakage = int(payload["leakage_bits"])
            return

        # --- handshake packets ---
        if kind == "hs_hello":
            pub = base64.b64decode(payload["pub_b64"])
            nonce = base64.b64decode(payload["nonce_b64"])
            if self.hs is None:
                self._stashed_peer_hello = (pub, nonce)
            else:
                hs_receive_hello(self.hs, pub, nonce)
            return

        if kind == "hs_auth":
            self._peer_auth_tag = base64.b64decode(payload["tag_b64"])
            return

    # ------------------- local derive aligned stream -------------------

    def derive_aligned_stream(self) -> Dict[str, Any]:
        assert self.session_id is not None
        mags = resample_linear(
            self.samples,
            self.cfg.rate_hz,
            self.cfg.duration_s,
            gyro_weight=self.cfg.gyro_weight,
        )
        hp = highpass(mags, self.cfg.hp_window)
        qm = quality_metrics(hp)
        if not qm["ok"]:
            raise RuntimeError(f"quality reject: {qm}")
        bits_opt, mask, qdbg = quantize_sign_guard(
            hp, guard_sigma=self.cfg.guard_sigma, include_diff_bit=self.cfg.include_diff_bit
        )
        self.bits_opt = bits_opt
        self.mask = mask
        return {"quality": qm, "quant": qdbg}

    async def exchange_masks_and_extract_bits(self) -> Dict[str, Any]:
        assert self.mask is not None and self.bits_opt is not None
        n = len(self.mask)

        await self.notify("mask", {
            "n": n,
            "mask_b64": base64.b64encode(pack_mask(self.mask)).decode(),
        })

        # wait peer mask
        t0 = time.time()
        while self.peer_mask is None and time.time() - t0 < 20.0:
            await asyncio.sleep(0.05)
        if self.peer_mask is None:
            raise RuntimeError("peer mask not received")

        if len(self.peer_mask) != n:
            raise RuntimeError(f"mask length mismatch: self={n}, peer={len(self.peer_mask)}")

        bits, dbg = intersect_and_extract(self.bits_opt, self.mask, self.peer_mask)
        self.bits = bits
        return dbg

    async def exchange_bitlens(self) -> Dict[str, Any]:
        if self.bits is None:
            raise RuntimeError("bits not ready")
        await self.notify("bitlen", {"n_bits": len(self.bits)})

        t0 = time.time()
        while self.peer_bitlen is None and time.time() - t0 < 20.0:
            await asyncio.sleep(0.05)
        if self.peer_bitlen is None:
            raise RuntimeError("peer bitlen not received")

        self.n_agreed = min(len(self.bits), int(self.peer_bitlen))
        self.bits = self.bits[:self.n_agreed]
        return {"self_bits": len(self.bits), "peer_bits": int(self.peer_bitlen), "n_agreed": self.n_agreed}

    async def run_cascade(self) -> Dict[str, Any]:
        if self.n_agreed is None or self.bits is None or self.session_id is None:
            raise RuntimeError("need n_agreed and bits first")
        if self.role != "bob":
            return {"note": "alice serves cascade only"}

        seed = sha256(b"TACCV2|cascade|" + self.session_id)
        self.cascade_ready = False
        self.cascade_leakage = None

        await self.notify("cascade_setup", {
            "n_bits": self.n_agreed,
            "rounds": self.cfg.cascade_rounds,
            "initial_block": self.cfg.initial_block,
            "seed_b64": base64.b64encode(seed).decode(),
        })

        t0 = time.time()
        while (not self.cascade_ready) and (time.time() - t0 < 10.0):
            await asyncio.sleep(0.05)
        if not self.cascade_ready:
            raise RuntimeError("cascade_ready not received")

        rounds = build_rounds(self.n_agreed, self.cfg.cascade_rounds, self.cfg.initial_block, seed=seed)
        client = self

        class WSOracle:
            async def parity_list(self, r: int) -> List[int]:
                resp = await client.request("cascade_parity_list_req", {"round": r})
                n_bits = int(resp["n_bits"])
                packed = base64.b64decode(resp["parities_b64"])
                return unpack_bits(packed, n_bits=n_bits)

            async def range_parity(self, r: int, lo: int, hi: int) -> int:
                resp = await client.request("cascade_range_parity_req", {"round": r, "lo": lo, "hi": hi})
                return int(resp["parity"])

        reconciler = BobCascadeReconciler(self.bits, rounds, oracle=WSOracle())
        b_rec, stats = await reconciler.reconcile()
        self.bits = b_rec
        self.cascade_leakage = int(stats.get("leakage_bits", 0))

        await self.notify("cascade_done", {"leakage_bits": self.cascade_leakage, "stats": stats})
        return stats

    async def derive_and_commit_kp(self, leakage_bits: int) -> Dict[str, Any]:
        assert self.session_id is not None
        if self.bits is None:
            raise RuntimeError("bits not ready")

        recon_th = self.recon_transcript_hash()
        kp, dbg = derive_kp(
            self.bits,
            session_id=self.session_id,
            leakage_bits=leakage_bits,
            recon_transcript_hash=recon_th,
        )
        self.kp = kp
        self.commit = kp_commit(kp, self.session_id, recon_th)

        # Commit messages are NOT part of recon transcript (avoids circularity),
        # but they still carry monotonic seq for replay protection.
        self._seq_out += 1
        commit_b64 = base64.b64encode(self.commit).decode()
        await self._send({"type": "commit", "payload": {"commit_b64": commit_b64, "seq": self._seq_out}})

        return {"kp": dbg, "sas6": sas6(kp, self.session_id), "commit_b64": commit_b64}

    async def wait_peer_commit(self):
        t0 = time.time()
        while self.peer_commit is None and time.time() - t0 < 20.0:
            await asyncio.sleep(0.05)
        if self.peer_commit is None:
            raise RuntimeError("peer commit not received")

    def commit_match(self) -> bool:
        if self.commit is None or self.peer_commit is None:
            return False
        return hmac.compare_digest(self.commit, self.peer_commit)

    async def run_handshake(self) -> Dict[str, Any]:
        if self.kp is None or self.session_id is None:
            raise RuntimeError("need kp")

        recon_th = self.recon_transcript_hash()

        # Canonical commit ordering (alice_commit, bob_commit) regardless of local role
        if self.commit is None or self.peer_commit is None:
            raise RuntimeError("need both commits before handshake")
        if self.role == "alice":
            alice_commit = self.commit
            bob_commit = self.peer_commit
        else:
            alice_commit = self.peer_commit
            bob_commit = self.commit

        self.hs = hs_init(self.role, self.session_id, self.kp, recon_th, alice_commit, bob_commit)

        # apply early peer hello if it arrived before hs init
        if self._stashed_peer_hello is not None:
            pub, nonce = self._stashed_peer_hello
            hs_receive_hello(self.hs, pub, nonce)
            self._stashed_peer_hello = None

        await self.notify("hs_hello", hs_message_hello(self.hs))

        # wait peer hello
        t0 = time.time()
        while (self.hs.peer_pub_raw is None) and time.time() - t0 < 20.0:
            await asyncio.sleep(0.05)
        if self.hs.peer_pub_raw is None:
            raise RuntimeError("peer handshake hello not received")

        hs_derive_master(self.hs)
        my_tag = hs_auth_tag(self.hs)
        await self.notify("hs_auth", {"tag_b64": base64.b64encode(my_tag).decode()})

        t0 = time.time()
        while self._peer_auth_tag is None and time.time() - t0 < 20.0:
            await asyncio.sleep(0.05)
        if self._peer_auth_tag is None:
            raise RuntimeError("peer handshake auth not received")

        if not hs_verify_peer_tag(self.hs, self.peer_role, self._peer_auth_tag):
            raise RuntimeError("handshake auth failed (MITM or mismatched Kp)")

        send_k, recv_k = hs_derive_session_keys(self.hs)
        self.send_key, self.recv_key = send_k, recv_k
        return {
            "master_fp": hashlib.sha256(self.hs.master).hexdigest()[:16],
            "send_fp": hashlib.sha256(send_k).hexdigest()[:16],
            "recv_fp": hashlib.sha256(recv_k).hexdigest()[:16],
        }

    async def pairing_flow(self) -> Dict[str, Any]:
        # reset transient state
        self._peer_auth_tag = None
        self._stashed_peer_hello = None
        self.cascade_ready = False
        self.cascade_leakage = None

        # derive aligned stream
        aligned = self.derive_aligned_stream()

        # exchange masks + extract bits
        mask_dbg = await self.exchange_masks_and_extract_bits()

        # NOTE: mask leakage is not modeled as "bits leaked" (too hand-wavy);
        # we compensate via safety margins in Kp derivation.
        leakage = 0

        # exchange bit lengths (agree on n)
        bitlen_dbg = await self.exchange_bitlens()

        # cascade (bob drives)
        cascade_dbg = await self.run_cascade()

        # Wait for cascade leakage figure (Bob sends cascade_done; Bob also sets it locally)
        t0 = time.time()
        while self.cascade_leakage is None and time.time() - t0 < 20.0:
            await asyncio.sleep(0.05)
        if self.cascade_leakage is None:
            raise RuntimeError("cascade_done/leakage not received")
        leakage += int(self.cascade_leakage)

        # derive & commit Kp
        kp_dbg = await self.derive_and_commit_kp(leakage_bits=leakage)

        await self.wait_peer_commit()
        cmatch = self.commit_match()
        if not cmatch:
            raise RuntimeError("Kp commitment mismatch (likely MITM or mismatch). Aborting before handshake.")

        hs_dbg = await self.run_handshake()

        return {
            "role": self.role,
            "aligned": aligned,
            "mask": mask_dbg,
            "bitlen": bitlen_dbg,
            "cascade": cascade_dbg,
            "leakage_bits_total": leakage,
            "kp": kp_dbg,
            "commit_match": cmatch,
            "handshake": hs_dbg,
            "ready": True,
        }
# ============================================================
# Local demo (no relay) — two-party interactive parity oracle
# ============================================================

def _simulate_imu(duration_s: float, rate_hz: float, seed: int) -> List[IMUSample]:
    rng = random.Random(seed)
    t0 = time.time()
    dt = 1.0 / rate_hz
    out: List[IMUSample] = []
    for i in range(int(duration_s * rate_hz)):
        u = i * dt
        base = math.sin(2.0 * math.pi * 2.0 * u) + 0.75 * math.sin(2.0 * math.pi * 5.1 * u + 0.4)
        base += 0.22 * math.sin(2.0 * math.pi * 11.3 * u + 1.2) * (0.4 + 0.6 * math.sin(2.0 * math.pi * 0.27 * u))
        ax = 1.0 * base + rng.gauss(0, 0.07)
        ay = 0.6 * base + rng.gauss(0, 0.07)
        az = 0.3 * base + rng.gauss(0, 0.07)
        gx = 0.8 * base + rng.gauss(0, 0.10)
        gy = 0.3 * base + rng.gauss(0, 0.10)
        gz = 0.2 * base + rng.gauss(0, 0.10)
        out.append(IMUSample(t=t0 + u, ax=ax, ay=ay, az=az, gx=gx, gy=gy, gz=gz))
    return out

def _induce_errors(bits: List[int], ber: float, seed: int) -> List[int]:
    rng = random.Random(seed)
    out = bits[:]
    for i in range(len(out)):
        if rng.random() < ber:
            out[i] ^= 1
    return out

def demo_local(ber: float = 0.15):
    cfg = ClientConfig()
    session_id = secrets.token_bytes(16)

    A = _simulate_imu(cfg.duration_s, cfg.rate_hz, seed=1337)
    B = _simulate_imu(cfg.duration_s, cfg.rate_hz, seed=1337)

    mags_a = resample_linear(A, cfg.rate_hz, cfg.duration_s, gyro_weight=cfg.gyro_weight)
    mags_b = resample_linear(B, cfg.rate_hz, cfg.duration_s, gyro_weight=cfg.gyro_weight)
    hp_a = highpass(mags_a, cfg.hp_window)
    hp_b = highpass(mags_b, cfg.hp_window)

    qa = quality_metrics(hp_a)
    qb = quality_metrics(hp_b)
    if not qa["ok"] or not qb["ok"]:
        raise RuntimeError(f"quality reject: {qa} {qb}")

    a_opt, a_mask, _ = quantize_sign_guard(hp_a, cfg.guard_sigma, cfg.include_diff_bit)
    b_opt, b_mask, _ = quantize_sign_guard(hp_b, cfg.guard_sigma, cfg.include_diff_bit)

    # exchange masks -> intersection
    inter = [ma and mb for ma, mb in zip(a_mask, b_mask)]
    a_bits = [int(a_opt[i]) for i, k in enumerate(inter) if k and a_opt[i] is not None]
    b_bits = [int(b_opt[i]) for i, k in enumerate(inter) if k and b_opt[i] is not None]
    n = min(len(a_bits), len(b_bits))
    a_bits = a_bits[:n]
    b_bits = b_bits[:n]
    b_bits = _induce_errors(b_bits, ber=ber, seed=4242)

    seed = sha256(b"TACCV2|cascade|" + session_id)
    rounds = build_rounds(n, cfg.cascade_rounds, cfg.initial_block, seed=seed)
    oracle = AliceParityOracle(a_bits, rounds)

    class LocalOracle:
        async def parity_list(self, r: int) -> List[int]:
            return oracle.parity_list(r)
        async def range_parity(self, r: int, lo: int, hi: int) -> int:
            return oracle.range_parity(r, lo, hi)

    reconciler = BobCascadeReconciler(b_bits, rounds, oracle=LocalOracle())
    b_rec, rec = asyncio.get_event_loop().run_until_complete(reconciler.reconcile())

    mism = sum(1 for i in range(n) if a_bits[i] != b_rec[i])
    ber_post = mism / n if n else 0.0

    leakage = int(rec["leakage_bits"])
    # Local demo transcript hash placeholder (in real WS mode this is computed from messages)
    recon_th = sha256(b"TACCV2|recon|demo_local|v1|" + session_id)
    kp, kpdbg = derive_kp(b_rec, session_id=session_id, leakage_bits=leakage, recon_transcript_hash=recon_th)

    print(json.dumps({
        "n_bits": n,
        "ber_injected": ber,
        "ber_post": ber_post,
        "leakage_bits_total": leakage,
        "cascade": rec,
        "kp": kpdbg,
        "sas6": sas6(kp, session_id),
        "note": "Local demo: interactive parity oracle + backtracking cascade.",
    }, indent=2))


# ============================================================
# CLI
# ============================================================

async def run_client(args):
    cfg = ClientConfig(
        rate_hz=args.rate,
        duration_s=args.duration,
        hp_window=args.hp_window,
        gyro_weight=args.gyro_weight,
        guard_sigma=args.guard_sigma,
        include_diff_bit=not args.no_diff,
        cascade_rounds=args.cascade_rounds,
        initial_block=args.block,
    )
    samples = load_samples(args.samples)
    c = WSClient(url=args.url, role=args.role, code=args.session, cfg=cfg, samples=samples)
    await c.connect()
    out = await c.pairing_flow()
    print(json.dumps(out, indent=2))

def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("demo_local")
    d.add_argument("--ber", type=float, default=0.15)

    c = sub.add_parser("client")
    c.add_argument("--url", type=str, default="ws://localhost:8000")
    c.add_argument("--session", type=str, required=True)
    c.add_argument("--role", type=str, choices=["alice", "bob"], required=True)
    c.add_argument("--samples", type=str, required=True)

    c.add_argument("--rate", type=float, default=100.0)
    c.add_argument("--duration", type=float, default=10.0)
    c.add_argument("--hp_window", type=int, default=25)
    c.add_argument("--gyro_weight", type=float, default=0.25)
    c.add_argument("--guard_sigma", type=float, default=0.35)
    c.add_argument("--no_diff", action="store_true")
    c.add_argument("--cascade_rounds", type=int, default=4)
    c.add_argument("--block", type=int, default=32)

    args = p.parse_args()
    if args.cmd == "demo_local":
        demo_local(ber=args.ber)
    elif args.cmd == "client":
        asyncio.run(run_client(args))

if __name__ == "__main__":
    main()
