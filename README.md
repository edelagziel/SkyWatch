## SkyWatch Policy-as-Code Analysis Engine

This repo contains the **Policy Logic** module selected in *SkyWatch – Module Selection for Low-Level Design & Implementation* and specified in *Appendix A — Low-Level Design (LLD): Policy-as-Code Analysis Engine (Policy Logic)*.

### What it does

- Evaluates a **normalized** `ResourceSnapshot` (control-plane metadata) against enabled **policy rules**
- Produces deterministic `findings` (severity, evidence, remediation) plus run `stats` and non-fatal `errors`

---

### How to run

**Requirements:** Python 3.10+

#### Option A – Run without installing (recommended for development)

From the project root directory:

```bash
PYTHONPATH=src python3 -m skywatch_policy_engine.cli \
  --snapshot examples/s3_snapshot_public_unencrypted.json \
  --policies examples/policies.json
```

- **Snapshot with findings** (public access, no encryption):
  ```bash
  PYTHONPATH=src python3 -m skywatch_policy_engine.cli \
    --snapshot examples/s3_snapshot_public_unencrypted.json \
    --policies examples/policies.json
  ```

- **Secure snapshot** (no findings):
  ```bash
  PYTHONPATH=src python3 -m skywatch_policy_engine.cli \
    --snapshot examples/s3_snapshot_secure_ok.json \
    --policies examples/policies.json
  ```

#### Option B – Install with venv

```bash
python3 -m venv .venv
source .venv/bin/activate   # On Windows: .venv\Scripts\activate
pip install -e .
```

Then run:

```bash
skywatch-eval --snapshot examples/s3_snapshot_public_unencrypted.json --policies examples/policies.json
```

#### Run the demo (both snapshots + tests)

```bash
bash demo_commands.sh
```

This runs both example snapshots, shows JSON output, and runs the test suite.

---

### Output format

| Option | Description |
|--------|-------------|
| (default) | **Text** output – summary, findings with severity and remediation |
| `--format json` | Full JSON output |
| `--format json --pretty` | Pretty-printed JSON with indentation |

Example for JSON:

```bash
PYTHONPATH=src python3 -m skywatch_policy_engine.cli \
  --snapshot examples/s3_snapshot_public_unencrypted.json \
  --policies examples/policies.json --format json --pretty
```

---

### Inputs

- **Snapshot JSON**: Normalized `ResourceSnapshot` (e.g. for S3: `public_access_block`, `acl_grants`, `bucket_policy`, `encryption`, `transport`)
- **Policies JSON**: List of enabled rules, with optional overrides for severity/params/suppression

Example files in `examples/`:

- `s3_snapshot_public_unencrypted.json` – snapshot with security findings
- `s3_snapshot_secure_ok.json` – compliant snapshot (no findings)
- `policies.json` – enabled rules configuration

---

### Outputs

- **Text format (default):** Run summary and a list of findings with title, severity, evidence, and remediation.
- **JSON format** (`--format json`): An `EvaluationResult` object with:
  - `findings` – list of findings
  - `stats` – rule counts and duration
  - `errors` – non-fatal errors (unknown rule, invalid schema, skipped missing data, etc.)
