# Methodology

## 1. Frozen benchmark

Every release pins:

- the OWASP BenchmarkPython repository and commit;
- the expected-results CSV and its SHA-256;
- the OpenAPI and crawler manifests and their SHA-256 values;
- the scorer and normalizer commit;
- Python, operating system, architecture, and container image digest;
- exact scanner versions, commands, configuration, rule/query packs, and account tier.

Publication runs use a clean checkout. Virtual environments, scanner caches, databases, logs, and result artifacts remain outside the scan target unless a tool requires otherwise and the exception is recorded.

## 2. Tracks

The default track uses each product's documented default security rules without suppressions or severity thresholds. Any custom rules, source/sink models, exclusions, or per-benchmark tuning belong to a separate tuned track.

Methods are reported as `sast`, `dast`, or `iast`. Cross-method comparisons are allowed, but no table may omit the method or runtime coverage.

## 3. Normalization

Each native finding is retained and converted into the common schema. The normalizer extracts:

- benchmark case ID;
- CWE values;
- tool rule ID and name;
- scanner-reported severity and confidence;
- file/line or HTTP route;
- message/evidence;
- raw artifact reference.

CWE aliases are frozen before scans. Unmapped or ambiguous findings remain visible and unscored until a versioned adjudication is published.

## 4. Strict scoring

A finding detects a benchmark case only when both are true:

1. the finding maps to that `BenchmarkTestNNNNN` case; and
2. the finding contains the case's expected CWE, after frozen alias normalization.

Multiple matching alerts count once per `(case ID, CWE)`. The scorer reports TP, FN, FP, TN, recall, miss rate, false-positive rate, precision, F1, accuracy, macro recall, macro FPR, and the OWASP score (`macro recall - macro FPR`).

Scanner severity is not part of the oracle and does not affect the primary score.

## 5. Runtime coverage

SAST tools analyze the clean source tree. DAST and IAST tools must also publish per-case request coverage.

For runtime methods:

- an exercised vulnerable case with no matching finding is a false negative;
- an exercised safe case with no matching finding is a true negative;
- an unexercised case is `not_run` and excluded from coverage-adjusted metrics;
- the strict all-case score remains available, with incompleteness prominently marked.

The traffic driver uses OWASP's crawler request templates. ZAP receives the seed traffic through its proxy before active scanning. Rig receives the same safe traffic once its runner is enabled.

The crawler templates are the canonical concrete requests. OpenAPI import is supplemental because the specification does not preserve every dynamic parameter name and safe value. A request counts as exercised only after a successful 2xx/3xx response; transport and HTTP errors remain visible as `not_run`. Seed-request coverage and ZAP active-scan traffic are separate artifacts.

## 6. Repetition and stability

Each scanner runs three times from clean state. Every run is scored independently. The publication reports recurrence of normalized findings and score range. Findings from separate runs are never unioned into a better headline score.

## 7. Verification and review

CI validates schemas, hashes raw artifacts, reruns normalization and scoring, and checks generated summaries. OWASP BenchmarkUtils may be used as a secondary cross-check, but the neutral scorer remains authoritative for this repository.

Before release, vendors may review commands, configuration, parser mappings, and factual errors. They cannot remove valid unfavorable results. Corrections are new tagged releases with an audit trail.

## 8. Limitations

BenchmarkPython 0.1 is preliminary and public. Products may have been trained or tuned against OWASP benchmarks. Results measure this pinned corpus and configuration, not universal real-world effectiveness.

Hosted rule engines can change without a CLI version change. Account tier, timestamps, organization policy, and any exposed engine version must therefore be retained.
