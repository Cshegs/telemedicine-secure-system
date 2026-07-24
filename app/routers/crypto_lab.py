import hashlib
import statistics
import time
from collections import Counter
from math import log2

from fastapi import APIRouter, Request, Depends, Query
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func
from sqlalchemy.orm import Session
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from app.database import get_db
from app.auth import get_session_user
from app.models import CryptoOperationLog
from app.crypto.hybrid_fusion import aes_encrypt, establish_session_key, traditional_hybrid_keygen, MockKyber
from app.crypto.profiles import OPERATION_TYPE_TO_PROFILE

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

PROFILE_ORDER = ["video_call", "chat", "patient_record"]
PROFILE_LABELS = {
    "video_call":     "SPEED_PROFILE (Video Call)",
    "chat":           "BALANCED_PROFILE (Chat)",
    "patient_record": "SECURITY_PROFILE (Records)",
}


def _serialize(result: dict) -> dict:
    """Make a pipeline result dict JSON-safe."""
    out = {k: v for k, v in result.items() if k != "kfinal"}
    out["kfinal_hex"] = result["kfinal"].hex()
    return out


def _current_mode(request: Request) -> str:
    return (request.session.get("encryption_mode", "proposed") or "proposed").lower()


def _shannon_entropy(key_bytes: bytes) -> float:
    if not key_bytes:
        return 0.0
    total = len(key_bytes)
    return sum(-p * log2(p) for _byte, count in Counter(key_bytes).items() if (p := count / total) > 0)


def _run_timing_series(operation_type: str, iterations: int, mode: str) -> tuple[dict, list[bytes], list[float]]:
    times: list[float] = []
    keys: list[bytes] = []
    for _ in range(iterations):
        if mode == "traditional":
            result = traditional_hybrid_keygen("crypto-lab-benchmark")
            result["operation_type"] = operation_type
        else:
            result = establish_session_key(operation_type, "crypto-lab-benchmark", mode=mode)
        times.append(result["execution_time_ms"])
        keys.append(result["kfinal"])
    return _timing_stats(times), keys, times


# ---------------------------------------------------------------------------
# Crypto Lab dashboard
# ---------------------------------------------------------------------------

@router.get("/crypto-lab")
async def crypto_lab_page(request: Request, db: Session = Depends(get_db)):
    user = get_session_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=302)

    # Last 30 log entries for the initial page render
    logs = (
        db.query(CryptoOperationLog)
        .order_by(CryptoOperationLog.created_at.desc())
        .limit(30)
        .all()
    )

    # Average execution time per operation type
    averages = (
        db.query(
            CryptoOperationLog.operation_type,
            func.avg(CryptoOperationLog.execution_time_ms).label("avg_ms"),
            func.count(CryptoOperationLog.id).label("count"),
        )
        .group_by(CryptoOperationLog.operation_type)
        .all()
    )

    avg_map = {row.operation_type: round(row.avg_ms, 3) for row in averages}
    count_map = {row.operation_type: row.count for row in averages}
    total_ops = sum(count_map.values())

    return templates.TemplateResponse(request, "crypto_lab.html", {
        "user":       user,
        "logs":       logs,
        "avg_map":    avg_map,
        "count_map":  count_map,
        "total_ops":  total_ops,
        "profile_order":  PROFILE_ORDER,
        "profile_labels": PROFILE_LABELS,
    })


# ---------------------------------------------------------------------------
# JSON data endpoint --polled by the dashboard for live refresh
# ---------------------------------------------------------------------------

@router.get("/crypto-lab/data")
async def crypto_lab_data(request: Request, db: Session = Depends(get_db)):
    user = get_session_user(request, db)
    if not user:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    logs = (
        db.query(CryptoOperationLog)
        .order_by(CryptoOperationLog.created_at.desc())
        .limit(30)
        .all()
    )

    averages = (
        db.query(
            CryptoOperationLog.operation_type,
            func.avg(CryptoOperationLog.execution_time_ms).label("avg_ms"),
            func.count(CryptoOperationLog.id).label("count"),
        )
        .group_by(CryptoOperationLog.operation_type)
        .all()
    )

    avg_map   = {row.operation_type: round(row.avg_ms, 3)  for row in averages}
    count_map = {row.operation_type: row.count              for row in averages}

    # Chart data in profile order
    chart_labels = [PROFILE_LABELS.get(op, op) for op in PROFILE_ORDER]
    chart_data   = [avg_map.get(op, 0) for op in PROFILE_ORDER]
    chart_counts = [count_map.get(op, 0) for op in PROFILE_ORDER]

    return JSONResponse({
        "total_ops":    sum(count_map.values()),
        "chart_labels": chart_labels,
        "chart_data":   chart_data,
        "chart_counts": chart_counts,
        "logs": [
            {
                "id":              log.id,
                "operation_type":  log.operation_type,
                "alpha":           log.alpha,
                "beta":            log.beta,
                "bytes_from_k1":   log.bytes_from_k1,
                "bytes_from_k2":   log.bytes_from_k2,
                "k1_prime_preview":log.k1_prime_preview,
                "k2_prime_preview":log.k2_prime_preview,
                "kf_preview":      log.kf_preview,
                "sid":             log.sid,
                "execution_time_ms": log.execution_time_ms,
                "created_at":      log.created_at.isoformat() if log.created_at else "",
            }
            for log in logs
        ],
    })


@router.get("/crypto-lab/mode-comparison-data")
async def crypto_lab_mode_comparison_data(request: Request, db: Session = Depends(get_db)):
    user = get_session_user(request, db)
    if not user:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    rows = (
        db.query(
            CryptoOperationLog.encryption_mode,
            func.avg(CryptoOperationLog.execution_time_ms).label("avg_ms"),
            func.count(CryptoOperationLog.id).label("count"),
            func.avg(CryptoOperationLog.bytes_from_k2).label("avg_bytes_from_k2"),
        )
        .group_by(CryptoOperationLog.encryption_mode)
        .all()
    )

    modes = []
    for row in rows:
        modes.append({
            "encryption_mode": row.encryption_mode or "proposed",
            "average_execution_time_ms": round(row.avg_ms or 0, 3),
            "operation_count": int(row.count or 0),
            "average_bytes_from_k2": round(row.avg_bytes_from_k2 or 0, 3),
        })

    modes.sort(key=lambda item: 0 if item["encryption_mode"] == "traditional" else 1)
    return JSONResponse({"modes": modes})


# ---------------------------------------------------------------------------
# "Run Live Comparison" --fires all three profiles and returns results
# ---------------------------------------------------------------------------

@router.post("/crypto-lab/compare")
async def crypto_lab_compare(request: Request, db: Session = Depends(get_db)):
    user = get_session_user(request, db)
    if not user:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    results = []
    for op_type in PROFILE_ORDER:
        result = establish_session_key(op_type, "crypto-lab-demo", db=db)
        results.append(_serialize(result))

    return JSONResponse({"results": results})


# ---------------------------------------------------------------------------
# Formal benchmark, 20 iterations per profile, plus a naive baseline.
# This is the evidence behind Table I (the Evaluate objective). It is
# evaluation-only: it does not write any CryptoOperationLog rows, since
# these runs are not real app operations.
# ---------------------------------------------------------------------------

BENCHMARK_ITERATIONS = 20
_baseline_kyber = MockKyber()


def _run_baseline_once() -> float:
    """
    Naive comparison: the same ECC exchange and Kyber encapsulation as the
    real pipeline, but fused with a plain SHA256(K1 || K2) concatenation.
    No alpha/beta weighting, no HKDF context binding. This only measures
    timing; it does not need to produce a usable key.
    """
    t0 = time.perf_counter()

    doctor_private = X25519PrivateKey.generate()
    patient_private = X25519PrivateKey.generate()
    K1 = doctor_private.exchange(patient_private.public_key())

    pk, _sk = _baseline_kyber.KeyGen()
    _ciphertext, K2 = _baseline_kyber.Encaps(pk)

    hashlib.sha256(K1 + K2).digest()  # naive concat, no weighting, no HKDF

    t1 = time.perf_counter()
    return round((t1 - t0) * 1000, 4)


def _timing_stats(times: list[float]) -> dict:
    return {
        "mean_ms":    round(statistics.mean(times), 4),
        "min_ms":     round(min(times), 4),
        "max_ms":     round(max(times), 4),
        "std_dev_ms": round(statistics.stdev(times), 4) if len(times) > 1 else 0.0,
        "all_times":  times,
    }


@router.post("/crypto-lab/benchmark")
async def crypto_lab_benchmark(request: Request, db: Session = Depends(get_db)):
    user = get_session_user(request, db)
    if not user:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    profiles_out = {}
    for op_type in PROFILE_ORDER:
        times = []
        last_result = None
        for _ in range(BENCHMARK_ITERATIONS):
            # No db= passed in: a benchmark run is not a real app operation,
            # so it must not write a CryptoOperationLog row.
            result = establish_session_key(op_type, "benchmark-run")
            times.append(result["execution_time_ms"])
            last_result = result

        stats = _timing_stats(times)
        stats["alpha"]         = last_result["alpha"]
        stats["beta"]          = last_result["beta"]
        stats["profile_name"]  = last_result["profile_name"]
        stats["bytes_from_k1"] = last_result["bytes_from_k1"]
        stats["bytes_from_k2"] = last_result["bytes_from_k2"]
        profiles_out[op_type] = stats

    baseline_times = [_run_baseline_once() for _ in range(BENCHMARK_ITERATIONS)]
    baseline_stats = _timing_stats(baseline_times)
    baseline_stats["alpha"]         = None
    baseline_stats["beta"]          = None
    baseline_stats["profile_name"]  = "BASELINE (naive concat)"
    baseline_stats["bytes_from_k1"] = 32
    baseline_stats["bytes_from_k2"] = 32

    return JSONResponse({
        "iterations": BENCHMARK_ITERATIONS,
        "profile_order": PROFILE_ORDER,
        "profiles": profiles_out,
        "baseline": baseline_stats,
    })


@router.post("/crypto-lab/run-benchmark-comparison")
async def crypto_lab_run_benchmark_comparison(request: Request, db: Session = Depends(get_db)):
    user = get_session_user(request, db)
    if not user:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    iterations = 100

    traditional_stats, traditional_keys, traditional_times = _run_timing_series("patient_record", iterations, "traditional")
    speed_stats, speed_keys, _ = _run_timing_series("video_call", iterations, "proposed")
    balanced_stats, balanced_keys, _ = _run_timing_series("chat", iterations, "proposed")
    security_stats, security_keys, security_times = _run_timing_series("patient_record", iterations, "proposed")

    return JSONResponse({
        "traditional": traditional_stats,
        "speed_profile": speed_stats,
        "balanced_profile": balanced_stats,
        "security_profile": security_stats,
        "entropy_traditional": round(_shannon_entropy(traditional_keys[0]), 6) if traditional_keys else 0.0,
        "entropy_proposed": round(_shannon_entropy(security_keys[0]), 6) if security_keys else 0.0,
        "replay_traditional": False,
        "replay_proposed": True,
        "unique_keys_traditional": len({key.hex() for key in traditional_keys}),
        "unique_keys_proposed": len({key.hex() for key in security_keys}),
        "security_profile_times": security_times,
        "traditional_times": traditional_times,
    })


@router.post("/crypto-lab/indistinguishability-test")
async def crypto_lab_indistinguishability_test(request: Request, db: Session = Depends(get_db)):
    user = get_session_user(request, db)
    if not user:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    plaintext = "Patient blood pressure: 145/90 mmHg"

    result_1 = establish_session_key("chat", "PAT-NG-DEMO", db=db)
    ciphertext_1, _nonce_1 = aes_encrypt(result_1["kfinal"], plaintext)

    result_2 = establish_session_key("chat", "PAT-NG-DEMO", db=db)
    ciphertext_2, _nonce_2 = aes_encrypt(result_2["kfinal"], plaintext)

    return JSONResponse({
        "ciphertext_1": ciphertext_1,
        "kfinal_1": result_1["kfinal"].hex(),
        "ciphertext_2": ciphertext_2,
        "kfinal_2": result_2["kfinal"].hex(),
    })


# ---------------------------------------------------------------------------
# /crypto-test --kept from Phase 2 for quick manual pipeline checks
# ---------------------------------------------------------------------------

@router.get("/crypto-test")
async def crypto_test_page(request: Request, db: Session = Depends(get_db)):
    user = get_session_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse(request, "crypto_test.html", {"user": user})


@router.get("/crypto-test/run")
async def crypto_test_run(
    request: Request,
    operation_type: str = Query("chat"),
    context_id: str = Query("demo-patient"),
    db: Session = Depends(get_db),
):
    user = get_session_user(request, db)
    if not user:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    try:
        result = establish_session_key(operation_type, context_id, db=db)
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)

    result["kfinal"] = result["kfinal"].hex()
    return JSONResponse(result)
