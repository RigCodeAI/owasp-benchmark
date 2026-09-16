# OWASP BenchmarkPython Scanner Comparison

Reproducible comparison of security testing tools against OWASP BenchmarkPython's fixed answer key.

The initial tool matrix is:

| Tool | Method | Status |
| --- | --- | --- |
| Rig | IAST / runtime | Planned; runner disabled until the CLI contract is ready |
| Semgrep | SAST | Planned |
| Snyk Code | SAST | Planned |
| CodeQL | SAST / taint analysis | Planned |
| OWASP ZAP | DAST | Planned |

CodeQL is classified as SAST, not DAST. Results may still be compared across methods, but every table must retain the method label and runtime coverage must be reported separately.

## Research question

The preregistered hypothesis is that, on cases fully exercised by every applicable tool, runtime IAST will achieve higher recall than DAST, and DAST will achieve higher recall than SAST. This repository is designed to **test** that hypothesis. It will publish contrary results unchanged if the data does not support it.

## Ground truth

The oracle is OWASP BenchmarkPython's versioned `expectedresults-0.1.csv`, not any scanner's output:

- 1,230 cases
- 452 deliberately vulnerable cases
- 778 safe controls
- 14 CWE categories

The exact upstream commit and artifact hashes are pinned in [`benchmark.lock.json`](benchmark.lock.json).

## Reproducibility promises

This project distinguishes three levels:

1. **Score verification:** anyone can recompute published scores from the retained normalized findings and pinned ground truth.
2. **Artifact verification:** anyone can verify checksums and re-normalize retained raw JSON/SARIF where redistribution is permitted.
3. **Scanner reproduction:** rerunning a commercial or hosted scanner may require the reader's own account, license, and credentials.

No credentials, tokens, organization identifiers, or proprietary license files belong in this repository.

## DAST and IAST traffic

BenchmarkPython already includes two useful inputs:

- `data/openapi.yaml` lists the benchmark operations.
- `data/benchmark-crawler-http.xml` contains one concrete safe request template per benchmark case, including query parameters, form fields, headers, and cookies.

[`tools/traffic.py`](tools/traffic.py) converts the crawler XML into a machine-readable request manifest or replays it through an HTTP proxy. The intended ZAP workflow is:

1. start BenchmarkPython in an isolated network;
2. start ZAP as a proxy/daemon;
3. replay all 1,230 safe seed requests through ZAP;
4. import the pinned OpenAPI document;
5. run ZAP active scanning over the recorded endpoints;
6. export SARIF/JSON plus per-case traffic coverage.

The same safe replay can later drive Rig. A safe case that was never exercised is `not_run`, never a true negative.

The traffic tool refuses non-loopback targets by default. `--allow-remote` exists for an explicitly isolated container or test host; never use it against an unrelated system.

## Quick verification

```sh
python3 -m unittest discover -s tests -v
python3 tools/score.py \
  --expected /path/to/BenchmarkPython/expectedresults-0.1.csv \
  --findings path/to/normalized.jsonl \
  --output score.json
```

To fetch the pinned benchmark into the ignored `benchmark/` directory:

```sh
./scripts/fetch-benchmark.sh
```

Generate the request manifest without starting the application:

```sh
python3 tools/traffic.py manifest \
  --crawler benchmark/data/benchmark-crawler-http.xml \
  --output artifacts/traffic-manifest.json
```

For an all-ZAP workflow, generate a deterministic HAR from the same XML and use the checked-in Automation Framework template:

```sh
python3 tools/traffic.py har \
  --crawler benchmark/data/benchmark-crawler-http.xml \
  --base-url http://benchmark:8000 \
  --allow-remote \
  --output artifacts/benchmark-safe.har

# Validate against the exact ZAP image selected for the release.
zap.sh -cmd -autocheck configs/zap-automation.example.yaml
```

Here `benchmark` is an isolated container-network service name, which is why the explicit remote-host override is present. The HAR import sends the safe seed requests; ZAP's `activeScan` job supplies attack payloads. The OpenAPI file remains a useful endpoint cross-check, but it is not the canonical traffic source because it does not retain every concrete safe parameter name and value.

The vendor runner scripts under `scripts/run/` are transparent starting points, not published results. Read each command, pin its mutable rules or query packs, and write artifacts outside the target tree before a release run.

## Publication policy

- Every scanner runs against a clean pinned target.
- Baseline configurations use all enabled default security rules with no severity filter or suppressions.
- Tool-specific tuning is a separate, clearly labeled track.
- Findings are scored by `(BenchmarkTest ID, expected CWE)` and deduplicated by that key.
- Raw alert totals are reported separately from case counts.
- Unmapped findings are retained for review.
- DAST/IAST results are incomplete unless route coverage is complete.
- Each release contains three runs per tool; instability is published, never replaced with an optimistic union.
- Corrections are versioned and documented in [`CORRECTIONS.md`](CORRECTIONS.md).

See [`METHODOLOGY.md`](METHODOLOGY.md) for the full protocol.

See [`EXECUTION_PLAN.md`](EXECUTION_PLAN.md) for the coordinator and subagent runbook covering setup, three-run execution, independent review, and publication.

## Safety

BenchmarkPython is intentionally vulnerable. Run it only in an isolated environment bound to loopback or a private container network. Never point these scripts at a non-benchmark target.

## Licensing

The comparison harness is Apache-2.0 licensed. OWASP BenchmarkPython is GPL-3.0 and is fetched separately at its pinned upstream commit. Scanner binaries, rule packs, and generated reports remain subject to their respective licenses and terms.
