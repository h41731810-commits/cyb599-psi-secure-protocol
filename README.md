# CYB 599 Graduate Project: Privacy-Preserving Credential Matching via EC-PSI and Hybrid Authenticated Transport

**Author:** Hari Prasad Unnikurma  
**Course:** CYB 599 – Contemporary Developments (Northern Arizona University)  

## Overview
This repository implements and evaluates a two-party privacy-preserving credential verification prototype combining:
1. **Part 1 (Private Set Intersection):** Commutative Elliptic-Curve Diffie-Hellman PSI (ECDH-PSI) over Curve25519, allowing Party A (Client Organization) and Party B (Verification Organization) to compute their set intersection without revealing non-matching identifiers.
2. **Part 2 (Hybrid Authenticated Encryption & Replay Resistance):** A secure transport layer combining **X25519** ephemeral-static key agreement, **HKDF-SHA-256** key derivation, **AES-256-GCM** authenticated encryption, **Ed25519** digital signatures, and stateful message-ID replay protection.

## Evaluated Configurations
- **Non-Private Baseline:** Unencrypted plaintext set exchange (`set(A) & set(B)`).
- **Parameter Set 1 (`PSI-Standard`):** ECDH-PSI wrapped in Hybrid Authenticated Transport returning full intersection elements ($A \cap B$).
- **Parameter Set 2 (`PSI-Cardinality`):** ECDH-PSI wrapped in Hybrid Authenticated Transport returning only intersection size ($|A \cap B|$) to minimize output disclosure.

## Repository Structure
- `protocol.py` — Core implementations of `SecureTransportChannel` (X25519/HKDF/AES-256-GCM/Ed25519), `PSIParty` (ECDH-PSI), and `run_non_private_baseline`.
- `evaluate.py` — Automated correctness/security test suite (tampering, replay, forgery, disjoint/overlapping sets) and multi-scale performance benchmarks ($N \in \{100, 500, 1000, 2500\}$).
- `run.sh` — Reproducible setup and execution script for a clean environment.
- `requirements.txt` — Pinned Python dependencies (`cryptography>=42.0.0`).

## Reproducible Quickstart (Clean Environment)

### Prerequisites
- Python 3.9+ (`python3` and `venv` module available)

### Option A: One-Command Execution (Linux / macOS / WSL / Git Bash)
```bash
chmod +x run.sh
./run.sh
