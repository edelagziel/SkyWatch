#!/bin/bash
# SkyWatch Policy Engine - Demo Commands
# להעתקה והדבקה במהלך ההקלטה

echo "=== 1. הצגת מבנה הפרויקט ==="
echo ""
tree -L 2 src/ 2>/dev/null || find src -type f -name "*.py" | head -10
echo ""
echo ""

echo "=== 2. הצגת קובץ Snapshot לדוגמה ==="
echo ""
head -15 examples/s3_snapshot_public_unencrypted.json
echo ""
echo ""

echo "=== 3. הרצת Policy Engine ==="
echo ""
PYTHONPATH=src python3 -m skywatch_policy_engine.cli \
  --snapshot examples/s3_snapshot_public_unencrypted.json \
  --policies examples/policies.json \
  --pretty
echo ""
echo ""

echo "=== 4. הרצת בדיקות ==="
echo ""
PYTHONPATH=src python3 -m unittest discover -s tests -p "test*.py" -v
echo ""
echo ""

echo "=== 5. סטטיסטיקות נוספות ==="
echo ""
echo "מספר findings לפי חומרה:"
PYTHONPATH=src python3 -m skywatch_policy_engine.cli \
  --snapshot examples/s3_snapshot_public_unencrypted.json \
  --policies examples/policies.json 2>/dev/null | \
  python3 -c "import sys, json; data=json.load(sys.stdin); \
  from collections import Counter; \
  sev = Counter(f['severity'] for f in data['findings']); \
  print('\n'.join(f'{k}: {v}' for k,v in sev.items()))"
echo ""
