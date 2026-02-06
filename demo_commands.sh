#!/bin/bash
# SkyWatch Policy Engine - Demo Commands
# Copy and paste these during the demo.

echo "=== 1. Project structure ==="
echo ""
tree -L 2 src/ 2>/dev/null || find src -type f -name "*.py" | head -10
echo ""
echo ""

echo "=== 2. Example snapshot file ==="
echo ""
head -15 examples/s3_snapshot_public_unencrypted.json
echo ""
echo ""

echo "=== 3. Run Policy Engine (snapshot with findings) ==="
echo ""
PYTHONPATH=src python3 -m skywatch_policy_engine.cli \
  --snapshot examples/s3_snapshot_public_unencrypted.json \
  --policies examples/policies.json
echo ""
echo ""

echo "=== 3b. Run Policy Engine (secure snapshot - no findings) ==="
echo ""
PYTHONPATH=src python3 -m skywatch_policy_engine.cli \
  --snapshot examples/s3_snapshot_secure_ok.json \
  --policies examples/policies.json
echo ""
echo ""

echo "=== 3c. Run Policy Engine (JSON format) ==="
echo ""
PYTHONPATH=src python3 -m skywatch_policy_engine.cli \
  --snapshot examples/s3_snapshot_public_unencrypted.json \
  --policies examples/policies.json \
  --format json --pretty
echo ""
echo ""

echo "=== 4. Run tests ==="
echo ""
PYTHONPATH=src python3 -m unittest discover -s tests -p "test*.py" -v
echo ""
echo ""

echo "=== 5. Findings by severity ==="
echo ""
echo "Findings count by severity:"
PYTHONPATH=src python3 -m skywatch_policy_engine.cli \
  --snapshot examples/s3_snapshot_public_unencrypted.json \
  --policies examples/policies.json --format json 2>/dev/null | \
  python3 -c "import sys, json; data=json.load(sys.stdin); \
  from collections import Counter; \
  sev = Counter(f['severity'] for f in data['findings']); \
  print('\n'.join(f'{k}: {v}' for k,v in sev.items()))"
echo ""
