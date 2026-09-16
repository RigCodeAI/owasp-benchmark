# Limitations

- OWASP BenchmarkPython 0.1 is preliminary.
- The corpus is public and may be familiar to scanner vendors.
- SAST, DAST, and IAST observe different evidence and are not interchangeable.
- Runtime tools require complete request coverage; missing traffic can look like a clean result.
- The ground truth defines test ID, vulnerability status, and CWE, but not severity.
- Hosted scanner backends can drift independently of their CLI versions.
- Commercial accounts, entitlements, and rate limits can affect reproducibility.
- A finding outside the official oracle may be a genuine additional issue; it is retained but not silently added to the answer key.
- A single product per runtime method cannot prove a universal method ordering; product, rules, configuration, and modality are confounded.
- Some intentionally unusual header names may be rejected by standards-compliant HTTP clients and must be published as `not_run`, not hidden.
