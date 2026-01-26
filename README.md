 ## SkyWatch Policy-as-Code Analysis Engine
 
 This repo contains the **Policy Logic** module selected in *SkyWatch – Module Selection for Low-Level Design & Implementation* and specified in *Appendix A — Low-Level Design (LLD): Policy-as-Code Analysis Engine (Policy Logic)*.
 
 ### What it does
 
 - Evaluates a **normalized** `ResourceSnapshot` (control-plane metadata) against enabled **policy rules**
 - Produces deterministic `findings` (severity, evidence, remediation) plus run `stats` and non-fatal `errors`
 
 ### Quick start
 
 1. Create a venv and install:
 
 ```bash
 python -m venv .venv
 source .venv/bin/activate
 pip install -e .
 ```
 
 2. Run an evaluation using the included examples:
 
 ```bash
 skywatch-eval --snapshot examples/s3_snapshot_public_unencrypted.json --policies examples/policies.json
 ```
 
 ### Inputs
 
 - **Snapshot JSON**: provider-agnostic `ResourceSnapshot` with `metadata` containing normalized keys (for S3: `public_access_block`, `acl_grants`, `bucket_policy`, `encryption`, `transport`)
 - **Policies JSON**: enabled rules (IDs), optional per-rule overrides (severity/params/suppression)
 
 ### Outputs
 
 - Writes a single `EvaluationResult` JSON to stdout with:
   - `findings`: list of findings
   - `stats`: rule counts + duration
   - `errors`: rule-level non-fatal errors (unknown rule, invalid schema, missing data skip, etc.)
