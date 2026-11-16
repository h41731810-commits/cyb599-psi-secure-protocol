#!/usr/bin/env bash
set -euo pipefail

echo "=== CYB 599 Graduate Project: Clean Environment Setup & Evaluation ==="

# Create isolated virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install exact dependencies
pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet

# Run correctness suite and performance benchmarks
python3 evaluate.py

echo "=== Evaluation Complete ==="
