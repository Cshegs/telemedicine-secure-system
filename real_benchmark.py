import sys, statistics, platform, time
sys.path.insert(0, ".")
import oqs, cryptography
from app.crypto import hybrid_fusion as hf
from app.crypto.profiles import SPEED_PROFILE, BALANCED_PROFILE, SECURITY_PROFILE

N = 100

def run(profile_key, mode):
    times = []
    sizes = None
    for _ in range(N):
        if mode == "traditional":
            r = hf.traditional_hybrid_keygen("benchmark")
        else:
            r = hf.establish_session_key(profile_key, "benchmark", mode="proposed")
        times.append(r["execution_time_ms"])
        sizes = (r["kem_alg"], r["kem_public_key_bytes"], r["kem_ciphertext_bytes"])
    return times, sizes

print("=== ENVIRONMENT (real, this run) ===")
print("Python:", platform.python_version())
print("Platform:", platform.platform())
print("cryptography lib:", cryptography.__version__)
print("liboqs-python:", oqs.oqs_python_version())
print("liboqs core:", oqs.oqs_version())
print("Traditional-baseline ML-KEM alg:", hf.TRADITIONAL_ML_KEM_ALG)
import subprocess
cpu = subprocess.run(["grep", "model name", "/proc/cpuinfo"], capture_output=True, text=True).stdout.splitlines()
print("CPU:", cpu[0].split(":")[1].strip() if cpu else "unknown")
print("Date (UTC):", time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()))
print()

# v3: each profile now selects a different ML-KEM parameter set (see
# app/crypto/profiles.py). The traditional baseline stays fixed at
# ML-KEM-768 -- the parameter set most healthcare PQC guidance recommends
# as a general-purpose default -- with no adaptivity and no context
# binding, so this benchmark isolates what per-operation algorithm
# selection (Step 2) and HKDF context binding (Step 5) each cost/buy.
configs = [
    ("traditional",    "traditional", "TRADITIONAL_BASELINE (fixed ML-KEM-768, no adaptivity)"),
    ("video_call",      "proposed",   f"SPEED_PROFILE ({SPEED_PROFILE['kem_alg']})"),
    ("chat",             "proposed",  f"BALANCED_PROFILE ({BALANCED_PROFILE['kem_alg']})"),
    ("patient_record",  "proposed",   f"SECURITY_PROFILE ({SECURITY_PROFILE['kem_alg']})"),
]

print(f"=== {N}-ITERATION BENCHMARK (real ML-KEM, this run) ===")
print(f"{'Configuration':<40} {'Mean(ms)':>10} {'Min(ms)':>10} {'Max(ms)':>10} {'StdDev(ms)':>12}")
results = {}
size_info = {}
for key, mode, label in configs:
    times, sizes = run(key, mode)
    mean = statistics.mean(times)
    mn = min(times)
    mx = max(times)
    sd = statistics.stdev(times)
    results[label] = (mean, mn, mx, sd)
    size_info[label] = sizes
    print(f"{label:<40} {mean:>10.4f} {mn:>10.4f} {mx:>10.4f} {sd:>12.4f}")

print()
print("=== real key/ciphertext sizes (bytes), this run ===")
print(f"{'Configuration':<40} {'Alg':>12} {'PubKey':>8} {'Ciphertext':>10}")
for label, (alg, pk_bytes, ct_bytes) in size_info.items():
    print(f"{label:<40} {alg:>12} {pk_bytes:>8} {ct_bytes:>10}")

baseline_key = "TRADITIONAL_BASELINE (fixed ML-KEM-768, no adaptivity)"
baseline_mean = results[baseline_key][0]
print()
print("=== vs traditional (fixed ML-KEM-768) baseline ===")
for label, (mean, mn, mx, sd) in results.items():
    if label == baseline_key:
        continue
    pct = (baseline_mean - mean) / baseline_mean * 100
    print(f"{label}: {pct:+.1f}% vs baseline (positive = faster)")
