import json
import os
import statistics
import time
from typing import List, Tuple

from cryptography.exceptions import InvalidSignature, InvalidTag

from protocol import (
    EndpointIdentity,
    SecureTransportChannel,
    run_non_private_baseline,
    run_private_psi_session,
)


def generate_synthetic_datasets(n: int, overlap_ratio: float = 0.25) -> Tuple[List[str], List[str], List[str]]:
    """Generates synthetic employee/applicant IDs for Party A and Party B with known overlap."""
    overlap_count = int(n * overlap_ratio)
    unique_count = n - overlap_count

    shared_ids = [f"EMP-SHARED-{i:06d}" for i in range(overlap_count)]
    only_a = [f"EMP-CLIENTA-{i:06d}" for i in range(unique_count)]
    only_b = [f"EMP-VERIFYB-{i:06d}" for i in range(unique_count)]

    set_a = shared_ids + only_a
    set_b = shared_ids + only_b
    return set_a, set_b, sorted(shared_ids)


def run_correctness_and_security_tests() -> None:
    print("=" * 75)
    print("1. CORRECTNESS & ADVERSARIAL SECURITY TEST SUITE")
    print("=" * 75)

    # Test 1: Partial Overlap Exact Match (Parameter Set 1)
    set_a, set_b, expected = generate_synthetic_datasets(50, overlap_ratio=0.30)
    res_std, _ = run_private_psi_session(set_a, set_b, cardinality_only=False)
    res_base, _ = run_non_private_baseline(set_a, set_b)
    assert res_std["intersection"] == expected == res_base["intersection"], "Intersection mismatch!"
    assert res_std["cardinality"] == len(expected), "Cardinality mismatch!"
    print("[PASS] Test 1: Partial overlap (30%) matches ground truth and baseline.")

    # Test 2: Cardinality-Only Mode (Parameter Set 2 - Zero Element Leakage)
    res_card, _ = run_private_psi_session(set_a, set_b, cardinality_only=True)
    assert res_card["cardinality"] == len(expected), "Cardinality-only count mismatch!"
    assert res_card["intersection"] is None, "Cardinality mode leaked intersection elements!"
    print("[PASS] Test 2: Cardinality-only mode returns |A ∩ B| without disclosing IDs.")

    # Test 3: Disjoint Sets (Zero Overlap)
    disjoint_a = [f"A-{i}" for i in range(20)]
    disjoint_b = [f"B-{i}" for i in range(20)]
    res_disjoint, _ = run_private_psi_session(disjoint_a, disjoint_b, cardinality_only=False)
    assert res_disjoint["intersection"] == [] and res_disjoint["cardinality"] == 0
    print("[PASS] Test 3: Disjoint sets return empty intersection [].")

    # Test 4: Ciphertext Tampering Detection (AES-256-GCM + Ed25519)
    id_a = EndpointIdentity("Alice")
    id_b = EndpointIdentity("Bob")
    chan_a = SecureTransportChannel(id_a, id_b.signing_pub_bytes, id_b.kex_pub_bytes, "sess-01")
    chan_b = SecureTransportChannel(id_b, id_a.signing_pub_bytes, id_a.kex_pub_bytes, "sess-01")

    pkt = chan_a.seal_packet(b"SENSITIVE-HR-RECORD-9912")
    tampered = json.loads(pkt.decode("utf-8"))
    ct_bytes = bytearray.fromhex(tampered["ciphertext_and_tag"])
    ct_bytes[0] ^= 0xFF  # Flip bits in ciphertext
    tampered["ciphertext_and_tag"] = ct_bytes.hex()

    try:
        chan_b.open_packet(json.dumps(tampered).encode("utf-8"))
        raise AssertionError("Tampered packet was not rejected!")
    except (InvalidSignature, InvalidTag):
        print("[PASS] Test 4: Modified ciphertext rejected immediately by Ed25519/GCM verification.")

    # Test 5: Replay Attack Rejection
    valid_pkt = chan_a.seal_packet(b"SENSITIVE-HR-RECORD-9913")
    decrypted = chan_b.open_packet(valid_pkt)
    assert decrypted == b"SENSITIVE-HR-RECORD-9913"
    try:
        chan_b.open_packet(valid_pkt)  # Replay exact packet
        raise AssertionError("Replay packet was not rejected!")
    except ValueError:
        print("[PASS] Test 5: Replayed packet rejected by replay-protection state cache.")

    # Test 6: Forged Sender Signature Rejection
    eve = EndpointIdentity("Eve_Attacker")
    chan_eve = SecureTransportChannel(eve, id_b.signing_pub_bytes, id_b.kex_pub_bytes, "sess-01")
    forged_pkt = chan_eve.seal_packet(b"FORGED-RECORD")
    try:
        chan_b.open_packet(forged_pkt)
        raise AssertionError("Forged signature was not rejected!")
    except InvalidSignature:
        print("[PASS] Test 6: Forged message from unauthorized key rejected by Ed25519.")
    print()


def benchmark_configurations(dataset_sizes: List[int], trials: int = 5) -> List[dict]:
    print("=" * 75)
    print(f"2. PERFORMANCE & COMMUNICATION OVERHEAD BENCHMARKS ({trials} trials/config)")
    print("=" * 75)

    # Warmup run
    w_a, w_b, _ = generate_synthetic_datasets(25)
    run_private_psi_session(w_a, w_b, cardinality_only=False)

    summary_rows = []

    for n in dataset_sizes:
        set_a, set_b, expected = generate_synthetic_datasets(n, overlap_ratio=0.25)

        # Baseline measurements
        base_times, base_sizes = [], []
        for _ in range(trials):
            t0 = time.perf_counter()
            res, size_b = run_non_private_baseline(set_a, set_b)
            base_times.append((time.perf_counter() - t0) * 1000.0)
            base_sizes.append(size_b)
            assert res["intersection"] == expected

        # Parameter Set 1: PSI-Standard (Full Intersection + Hybrid Auth Encryption)
        std_times, std_sizes = [], []
        for _ in range(trials):
            t0 = time.perf_counter()
            res, size_b = run_private_psi_session(set_a, set_b, cardinality_only=False)
            std_times.append((time.perf_counter() - t0) * 1000.0)
            std_sizes.append(size_b)
            assert res["intersection"] == expected

        # Parameter Set 2: PSI-Cardinality (Cardinality-Only + Hybrid Auth Encryption)
        card_times, card_sizes = [], []
        for _ in range(trials):
            t0 = time.perf_counter()
            res, size_b = run_private_psi_session(set_a, set_b, cardinality_only=True)
            card_times.append((time.perf_counter() - t0) * 1000.0)
            card_sizes.append(size_b)
            assert res["cardinality"] == len(expected)

        row = {
            "dataset_size_n": n,
            "baseline_time_ms": round(statistics.mean(base_times), 3),
            "baseline_std_ms": round(statistics.stdev(base_times), 3),
            "baseline_bytes": int(statistics.mean(base_sizes)),
            "psi_standard_time_ms": round(statistics.mean(std_times), 3),
            "psi_standard_std_ms": round(statistics.stdev(std_times), 3),
            "psi_standard_bytes": int(statistics.mean(std_sizes)),
            "psi_cardinality_time_ms": round(statistics.mean(card_times), 3),
            "psi_cardinality_std_ms": round(statistics.stdev(card_times), 3),
            "psi_cardinality_bytes": int(statistics.mean(card_sizes)),
            "overhead_factor_time": round(statistics.mean(std_times) / max(statistics.mean(base_times), 1e-6), 1),
            "overhead_factor_bytes": round(statistics.mean(std_sizes) / statistics.mean(base_sizes), 2),
        }
        summary_rows.append(row)

    # Print formatted comparison table
    header = (
        f"{'N (Items)':<10} | {'Baseline (ms)':<14} | {'PSI-Std (ms)':<14} | "
        f"{'PSI-Card (ms)':<14} | {'Base Bytes':<11} | {'PSI Bytes':<11} | {'BW Ratio':<8}"
    )
    print(header)
    print("-" * len(header))
    for r in summary_rows:
        print(
            f"{r['dataset_size_n']:<10} | "
            f"{r['baseline_time_ms']:<14.3f} | "
            f"{r['psi_standard_time_ms']:<14.3f} | "
            f"{r['psi_cardinality_time_ms']:<14.3f} | "
            f"{r['baseline_bytes']:<11} | "
            f"{r['psi_standard_bytes']:<11} | "
            f"{r['overhead_factor_bytes']:<8.2f}x"
        )

    # Measure single-packet Hybrid Transport cryptographic overhead (Part 2)
    id_a = EndpointIdentity("Sender")
    id_b = EndpointIdentity("Recipient")
    chan_a = SecureTransportChannel(id_a, id_b.signing_pub_bytes, id_b.kex_pub_bytes, "bench-sess")
    chan_b = SecureTransportChannel(id_b, id_a.signing_pub_bytes, id_a.kex_pub_bytes, "bench-sess")

    sample_pt = b"A" * 1024  # 1 KB payload
    seal_times, open_times = [], []
    wire_len = 0
    for _ in range(100):
        t0 = time.perf_counter()
        pkt = chan_a.seal_packet(sample_pt)
        seal_times.append((time.perf_counter() - t0) * 1000.0)
        wire_len = len(pkt)

        t1 = time.perf_counter()
        chan_b.open_packet(pkt)
        open_times.append((time.perf_counter() - t1) * 1000.0)

    transport_metrics = {
        "plaintext_bytes": len(sample_pt),
        "wire_package_bytes": wire_len,
        "cryptographic_expansion_bytes": wire_len - len(sample_pt),
        "avg_seal_time_ms": round(statistics.mean(seal_times), 4),
        "avg_open_time_ms": round(statistics.mean(open_times), 4),
    }

    print("\n" + "=" * 75)
    print("3. PART 2 HYBRID TRANSPORT LAYER OVERHEAD (1 KB PAYLOAD, 100 ITERATIONS)")
    print("=" * 75)
    for k, v in transport_metrics.items():
        print(f"  {k}: {v}")

    output = {"psi_benchmarks": summary_rows, "hybrid_transport_metrics": transport_metrics}
    with open("results.json", "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)
    print("\nSaved full benchmark results to results.json.")
    return summary_rows


if __name__ == "__main__":
    run_correctness_and_security_tests()
    benchmark_configurations(dataset_sizes=[100, 500, 1000, 2500], trials=5)
