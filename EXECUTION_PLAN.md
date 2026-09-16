# Benchmark Execution Plan

This runbook is for a coordinator agent that will execute the Semgrep, Snyk Code, CodeQL, and OWASP ZAP baselines by delegating bounded work to subagents. It does not authorize changing the oracle, suppressing findings, weakening the scoring rules, or publishing incomplete work as a finished comparison.

## 1. Goal and completion criteria

Produce one auditable baseline release containing three independent runs for each scanner:

| Tool | Method | Required primary output |
| --- | --- | --- |
| Semgrep | SAST | SARIF |
| Snyk Code | SAST | SARIF |
| CodeQL | SAST / taint analysis | SARIF |
| OWASP ZAP | DAST | Traditional JSON, SARIF, and request coverage |

The release is complete only when:

- all scanners ran against the clean commit in `benchmark.lock.json`;
- exact tool, rule/query pack, and container versions are frozen;
- each successful run has raw output, normalized findings, a score, logs, a manifest, and checksums;
- ZAP has per-case runtime coverage and its active scan completed;
- an agent other than the scanner operator independently reproduced normalization and scoring;
- all denominators, failed runs, unmapped findings, and `not_run` cases are published;
- the comparison labels every tool as SAST or DAST and describes `IAST > DAST > SAST` as a tested hypothesis, not a guaranteed conclusion.

Rig is not part of this release. Add it later as IAST using the same traffic and evidence rules after its public runner contract is ready.

## 2. Coordinator and subagent boundaries

The coordinator owns the release ID, protocol freeze, task dispatch, final review, commits, tags, and publication. It must not quietly repair or discard an unfavorable result.

Use these subagent roles:

1. **Preflight agent:** validates the host, pinned benchmark, tool version, configuration, credentials, and clean scan target.
2. **Scanner operator:** runs one scanner's canary and three clean repetitions. It owns only that scanner's isolated worktree and output directory.
3. **Evidence reviewer:** works read-only from the retained artifacts, checks completeness, and independently reruns normalization and scoring.
4. **Release reviewer:** compares all accepted runs, checks the tables and limitations, and verifies that no failed or untested case disappeared.

Rules for delegation:

- Give every subagent a self-contained prompt with the repository path, release ID, scanner, files it owns, expected outputs, and acceptance criteria.
- A writing subagent must use its own isolated worktree. Read-only reviewers may run in parallel.
- Only the coordinator merges changes or pushes to the public repository.
- Run scanners serially by default. This prevents shared ports, caches, daemon state, target state, and host load from contaminating runs.
- Never place tokens, browser login results, organization IDs, or proprietary license files in prompts, logs, manifests, or Git.
- Authentication is a human gate. When Snyk needs login, the coordinator pauses and asks the user to complete `snyk auth` or provide `SNYK_TOKEN` in their own environment.

Scanner operators stage output outside Git, for example under `/tmp/owasp-benchmark-runs/<release-id>/<tool>/<run-id>/`. After independent acceptance, the coordinator copies only publishable artifacts into `runs/`. Failed attempts use distinct attempt IDs and are never overwritten.

## 3. Release and artifact layout

Choose an immutable release ID such as `2026-09-baseline-01` before resolving rules or running scanners.

```text
runs/<release-id>/
  release.json
  semgrep/
    run-1/
    run-2/
    run-3/
  snyk/
    run-1/
    run-2/
    run-3/
  codeql/
    run-1/
    run-2/
    run-3/
  zap/
    run-1/
    run-2/
    run-3/
results/<release-id>/
  summary.md
  summary.json
  summary.csv
```

Every `run-N` directory must contain:

```text
manifest.json
command.txt
version.txt or version.json
environment.json
stdout.log
stderr.log
raw.sarif
raw native output when available
normalized.jsonl
normalization.json
score.json
coverage.json                 # ZAP only
SHA256SUMS
```

Each manifest records a status from `PASS`, `FAILED_ENV`, `FAILED_SCAN`, `INVALID_OUTPUT`, `INCOMPLETE_COVERAGE`, or `NOT_RUN`, plus the benchmark and harness commits, artifact hashes, sanitized command, tool and engine versions, configuration hashes, UTC timestamps, platform details, exit code, and coverage reference when applicable. `SHA256SUMS` excludes itself.

Large transient files such as CodeQL databases, virtual environments, scanner caches, and ZAP sessions stay outside Git. If a vendor's terms prevent raw output redistribution, retain its checksum and mark the run as score-verifiable but not artifact-verifiable.

## 4. Phase 0: freeze and preflight

The coordinator dispatches a preflight agent before any scanner operator.

### Required checks

```sh
git status --short
./scripts/fetch-benchmark.sh
python3 tools/verify_lock.py --benchmark benchmark
python3 -m unittest discover -s tests -v
```

The preflight agent must also confirm:

- the harness commit and `benchmark.lock.json` hash;
- the benchmark checkout is clean and at the pinned commit;
- artifact directories are outside the scan target;
- one canonical SAST source scope is defined and hashed;
- sufficient disk space exists for three CodeQL databases and ZAP output;
- the alias file and scoring policy are frozen before looking at scanner results;
- system time, OS, architecture, CPU, RAM, and Python version can be recorded;
- licenses and vendor terms permit the intended artifact publication.

### Harness gates to close before the first publication run

The coordinator should assign one implementation worktree to close these gaps:

- create run manifests and `SHA256SUMS` automatically;
- validate manifests and normalized findings against the checked-in schemas;
- exclude CodeQL databases and other transient scanner state from Git;
- freeze Semgrep's resolved rule files rather than publishing only the mutable registry name;
- prepare a scanner-neutral SAST target that excludes upstream `results/`, scanner scripts, prior reports, virtual environments, and generated artifacts while retaining the application and its imports;
- make every runner record its exact source scope and handle documented finding exit codes without losing valid output;
- record CodeQL bundle and query-pack versions and hashes;
- create and test a private BenchmarkPython/ZAP container topology;
- validate `configs/zap-automation.example.yaml` against the pinned ZAP image;
- add a release aggregator that reports per-run results and stability without unioning findings.

Do not start the three-run baseline until these gates pass in CI.

## 5. Scanner sequence

Run the scanners in this order:

1. Semgrep
2. Snyk Code
3. CodeQL
4. OWASP ZAP

### Work packages

| Package | Owner | Depends on | Parallel work allowed |
| --- | --- | --- | --- |
| P0: protocol and environment freeze | Coordinator + preflight agent | None | Read-only host and license checks |
| P1: close harness gates | One implementation agent in an isolated worktree | P0 | Independent code review and test review |
| S1: Semgrep canary and runs | Semgrep operator | P1 | Semgrep evidence review after run 3 |
| S2: Snyk canary and runs | Snyk operator | S1 | Snyk evidence review after run 3 |
| S3: CodeQL canary and runs | CodeQL operator | S2 | CodeQL evidence review after run 3 |
| S4: ZAP topology, canary, and runs | ZAP operator | S3 | Coverage and SARIF review after run 3 |
| R1: aggregate and compare | Coordinator | Accepted S1-S4 | Independent release review |
| R2: publish | Coordinator only | Accepted R1 and green CI | None |

The serial order is the default reproducibility policy, not a technical limitation. The coordinator may parallelize read-only artifact reviews, documentation checks, and vendor-license research, but not scanner processes that share the host or target.

For every scanner, use the same state machine:

```text
preflight -> canary -> artifact review -> three clean runs -> independent review -> accept or rerun
```

A scanner process failure is an invalid run, not a false negative. Retain its logs outside the accepted three-run set, diagnose the failure, and restart from clean state.

## 6. Semgrep phase

### Freeze

- Install a pinned Semgrep CLI. Initial candidate: `1.177.0`.
- Resolve the intended default Python security rules once.
- Save the exact resolved rules or an immutable reference plus checksum, subject to the rules' license.
- Record whether login, proprietary rules, or Semgrep Code features are used. The baseline must not silently mix Community Edition and hosted rules.

### Canary and runs

```sh
SEMGREP_RULES=/absolute/path/to/frozen-rules.yml \
  ./scripts/run/semgrep.sh benchmark /absolute/path/to/run-1
```

Use a new output directory and clean scanner cache policy for each repetition. Do not add suppressions or a severity threshold.

During the canary, confirm the pinned Semgrep CLI's documented exit behavior. If it can return `1` for a completed scan with findings, fix the runner to require valid SARIF before deciding whether the run failed; do not let `set -e` discard a valid result.

### Acceptance gate

- SARIF exists and the scanner exited successfully.
- Version and rule checksum are identical across all three runs.
- The SARIF normalizer retains findings without case IDs or CWEs in diagnostics.
- Independent scoring reproduces every `score.json` byte-for-byte or explains harmless serialization differences.
- Finding-set changes between repetitions are reported.

## 7. Snyk Code phase

### Human authentication gate

The current local CLI candidate is `1.1306.3`. Use a writable cache outside the target:

```sh
SNYK_CACHE_PATH=/tmp/owasp-benchmark-snyk-cache snyk auth
SNYK_CACHE_PATH=/tmp/owasp-benchmark-snyk-cache snyk whoami
```

The user performs authentication. The agent records only the CLI version, scan time, account tier, and relevant policy/configuration—not credentials or private organization identifiers.

### Canary and runs

```sh
SNYK_CACHE_PATH=/tmp/owasp-benchmark-snyk-cache \
  ./scripts/run/snyk.sh benchmark /absolute/path/to/run-1
```

Snyk exit code `1` means findings were reported and is accepted by the runner. Other nonzero codes invalidate the run.

### Acceptance gate

- Snyk Code is enabled for the authenticated account.
- The CLI version, account tier, configuration, timestamps, and any exposed engine version are retained.
- All three SARIF files are parseable and independently scored.
- Hosted-engine drift and finding-set instability are shown rather than hidden.
- No source, token, cache, or account metadata is committed accidentally.

## 8. CodeQL phase

### Freeze

- Download a pinned official CodeQL bundle. Initial candidate: `2.27.0`.
- Verify the release checksum before extraction.
- Record `codeql version --format=json` and `codeql resolve qlpacks`.
- Use the bundle's pinned Python query pack and record the exact suite. The baseline suite is `python-security-extended.qls` unless the protocol freeze changes it before any scanner run.

### Canary and runs

```sh
PATH=/absolute/path/to/codeql:$PATH \
CODEQL_SUITE=codeql/python-queries:codeql-suites/python-security-extended.qls \
  ./scripts/run/codeql.sh benchmark /absolute/path/to/run-1
```

Create a fresh database for every repetition. Keep databases and extractor caches outside Git and outside the benchmark target.

### Acceptance gate

- Bundle, CLI, query pack, and suite are identical across repetitions.
- Database creation and analysis both completed without extraction errors.
- SARIF, normalization diagnostics, and scores exist for all three runs.
- The independent reviewer verifies the case ID and CWE mappings, especially results whose source and sink locations differ.
- CodeQL remains labeled SAST / taint analysis, never DAST.

## 9. OWASP ZAP phase

ZAP is the only runtime scanner in this release and must not run until its isolated topology and coverage proof work end to end.

### Required topology

Use a private container network containing:

- a BenchmarkPython container at the pinned source commit;
- a ZAP container pinned by version and image digest;
- a writable artifact mount visible to ZAP;
- no publicly exposed benchmark listener;
- no unrestricted runtime egress; use a controlled sink if a benchmark case requires an outbound destination;
- an optional loopback-only health endpoint for the coordinator.

The application container must use one production-style process without Flask debug mode or its reloader. Apply CPU, memory, and time limits, use fresh writable state for each run, and do not use privileged containers or broad host mounts.

Initial ZAP version candidate: `2.17.0`. The image digest, installed add-ons, automation plan, scan policy, and container runtime versions must be frozen.

The existing example assumes `http://benchmark:8000/benchmark`, while upstream BenchmarkPython normally starts with HTTPS on port 8443. The topology owner must make the application URL, generated HAR, ZAP context, health check, and active-scan URL agree before scanning.

### Traffic and scan stages

1. Start fresh application and ZAP containers.
2. Confirm the benchmark commit and application health.
3. Generate the deterministic request manifest and optional audit HAR from `benchmark-crawler-http.xml`.
4. Validate the Automation Framework plan with the pinned ZAP image.
5. Replay the crawler XML exactly once through the ZAP proxy, producing `coverage.json`.
6. Verify those 1,230 case IDs are present in ZAP history, then record the seed-traffic boundary.
7. Wait for passive scanning to finish.
8. Run the active scanner over the recorded benchmark scope.
9. Export traditional JSON plus SARIF.
10. Normalize and score with `coverage.json`.
11. Destroy the containers and session before the next repetition.

Before the first full run, use a small mapping canary to prove that ZAP output contains both the exact `BenchmarkTestNNNNN` from the request URL and an explicit CWE. If SARIF omits either, add and test a native-JSON adapter or a frozen versioned ZAP-alert-to-CWE mapping. Never infer CWE only from the benchmark route category.

The canonical proxy-seeding command is:

```sh
ZAP_PROXY=http://127.0.0.1:8080 \
  ./scripts/run/zap.sh benchmark https://127.0.0.1:8443 /absolute/path/to/run-1
```

That script currently handles seed traffic only; the topology implementation must continue with the active scan and artifact export. Keep the generated HAR as an auditable input, but do not also import it with `sendRequests: true`, because that would seed every request twice. The checked-in Automation Framework example must be updated accordingly before publication.

### Coverage and acceptance gate

- `planned` is 1,230 and every case has an explicit record.
- Only successful 2xx/3xx requests count as exercised under the current protocol.
- Transport failures and HTTP errors remain visible as `not_run`.
- Seed coverage is not mistaken for active-scan coverage.
- ZAP attacks query parameters, form bodies, cookies, and headers.
- Known unusual header-name cases are either successfully exercised or listed as predeclared `not_run`; they are never silently dropped.
- Active scan completed and produced both native JSON and SARIF.
- Alert-to-case and alert-to-CWE mappings pass independent review.
- An incomplete runtime run may be published as incomplete, but it cannot support the headline method comparison.

## 10. Independent evidence review

After each scanner finishes three candidate runs, dispatch a read-only evidence reviewer that did not operate the scanner.

For each run, the reviewer must:

1. Verify all listed files and checksums.
2. Confirm the manifest references the frozen harness and benchmark commits.
3. Re-run normalization from raw SARIF or JSON into a temporary directory.
4. Re-run scoring against the pinned CSV.
5. Compare regenerated findings and scores with the published artifacts.
6. Report raw finding count, unique `(case ID, CWE)` pairs, missing-case findings, missing-CWE findings, unmatched pairs, and unknown cases.
7. For ZAP, recompute coverage and confirm `not_run` handling.
8. Compare the three normalized finding sets and report instability.

The reviewer returns `ACCEPT`, `REJECT`, or `INCOMPLETE` with exact evidence. The coordinator must not override `REJECT` without fixing the defect and obtaining a fresh independent review.

## 11. Comparison and publication

Only accepted runs enter the main comparison. The release reviewer verifies that the summary reports, for every run and CWE:

```text
Method | Tool | Severity | Category | Caught / Vulnerable | Missed | False Positives / Safe | Recall
```

Also publish TP, FN, FP, TN, precision, F1, accuracy, macro recall, macro FPR, OWASP score, coverage, `not_run`, unmapped findings, run-to-run range, and finding recurrence.

Publication steps:

1. Regenerate summaries from committed normalized artifacts.
2. Run all tests and artifact verification in CI.
3. Review the diff for credentials and private identifiers.
4. Commit run artifacts without transient databases, caches, sessions, or dependencies.
5. Push a review branch and open a pull request.
6. Require independent methodology and artifact approval.
7. Merge, tag the immutable release, and attach oversized permitted raw artifacts to the GitHub release with checksums.
8. Add later corrections through `CORRECTIONS.md`; never rewrite a released score silently.

## 12. Failure and pause rules

- **Authentication required:** pause for the user; never request a token in chat or print it.
- **Dirty benchmark:** stop and create a fresh pinned checkout.
- **Scanner crash or timeout:** mark the attempt invalid, retain logs, diagnose, and rerun clean. Do not score it as misses.
- **Missing or truncated raw output:** reject the run.
- **Unexpected rule/query update:** freeze a new release ID or restart every affected scanner under the new lock.
- **Normalizer cannot map a material set of findings:** pause scoring and fix the adapter with tests before looking at headline results.
- **ZAP coverage below the frozen threshold:** mark the run incomplete and do not use it for the headline modality comparison.
- **Results contradict the hypothesis:** publish them unchanged.

## 13. Reusable dispatch prompts

The coordinator should paste the relevant prompt into a fresh subagent task and replace every angle-bracket placeholder. Do not assume a subagent can see earlier conversation context.

### Preflight or implementation agent

```text
You own <worktree/files>. Prepare release <release-id> of RigCodeAI/owasp-benchmark.
Do not run a scanner yet. Verify the pinned benchmark, harness tests, host prerequisites,
tool/version lock, artifact paths, schema validation, and credential boundaries. Close only
the named harness gaps, add tests, and return commands plus evidence. You are not alone in
the repository: do not modify files outside your ownership or revert others' work.
```

### Scanner operator

```text
You own scanner <tool> and output <isolated-path> for release <release-id>. Use only the
frozen benchmark commit, harness commit, tool version, and configuration in <lock-file>.
Run one canary, stop for artifact review, then run three fresh repetitions if approved.
Retain raw output, normalized findings, scores, logs, manifests, environment evidence, and
checksums. Do not alter the oracle, aliases, normalizer, scorer, or suppress findings. Treat
scanner failures as invalid runs. Never expose credentials. Return exact paths and commands.
```

### Evidence reviewer

```text
Read-only review of <tool> release <release-id>. Do not trust generated scores. Verify
checksums and manifests, regenerate normalized findings from raw artifacts, independently
rerun the scorer, audit unmapped and duplicate findings, compare all three repetitions, and
check coverage for runtime tools. Return ACCEPT, REJECT, or INCOMPLETE with exact evidence.
Do not edit or delete artifacts.
```

### Release reviewer

```text
Read-only final review of release <release-id>. Confirm four scanners have three accepted
runs, strict denominators are correct, method labels and ZAP coverage are visible, stability
is reported without unioning runs, failed attempts are disclosed, and all summaries can be
regenerated from committed artifacts. Check for secrets and prohibited artifacts. Return a
release decision and every blocking discrepancy.
```
