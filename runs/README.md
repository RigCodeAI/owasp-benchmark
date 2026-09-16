# Published runs

Each release run belongs in `runs/<release-id>/<tool>/` and contains a run manifest, command, version and environment evidence, raw output when redistribution is permitted, normalized JSONL, score JSON, coverage JSON for runtime methods, logs, and SHA-256 checksums.

Do not commit credentials or copy scanner artifacts whose license forbids redistribution. If raw output cannot be published, retain its checksum and clearly label the run as score-verifiable but not artifact-verifiable.
