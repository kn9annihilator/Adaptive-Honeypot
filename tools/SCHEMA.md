# Corpus Manifest / Acquisition v2

## Placement

Put `acquire_samples.py`, `test_acquire_samples.py`, and this `SCHEMA.md` in:

`D:\Honeypot\Codebase\tools\`

Keep `build_manifest.py` unchanged.

## Acquisition model

Candidate discovery and acquisition are separate.

`pending` in `candidate_manifest.csv` means that the candidate has not yet received an acquisition decision. It never means "download immediately".

Normal lifecycle:

`candidate -> queued -> download_started -> download_completed -> cryptographic_verification -> cryptographically_verified -> storage_started -> stored -> ready_for_analysis`

Alternate states:

- `duplicate`
- `download_failed`
- `integrity_failed`
- `storage_failed`

## Two validation boundaries

### 1. Candidate validation

Performed before network acquisition.

This can exclude a candidate for research-scope or metadata reasons (for example, a non-PE artifact). This is NOT a cryptographic-integrity rejection.

### 2. Cryptographic verification

Performed after download.

The SHA-256 calculated from the acquired sample must exactly match the expected MalwareBazaar SHA-256.

The final file at its canonical storage path is hashed again after the storage commit.

## Storage transaction

Downloads are written under:

`Corpus\.staging\<temporary-id>\sample`

Only after cryptographic verification succeeds is the staging directory atomically renamed to:

`Corpus\samples\quarantine\<SHA256>\`

The final file is hashed again after the rename.

Only then is the validated record appended to:

`Corpus\manifests\samples.jsonl`

If the process fails after canonical storage but before JSONL persistence, the verified sample is retained for audit/recovery rather than silently deleted. A later reconciliation step can identify such filesystem/manifest divergence.

## Performance properties

- SHA-256 uses 1 MiB streaming reads.
- Corpus identity is loaded once into a set; membership is O(1).
- The JSONL writer is opened once per acquisition run rather than once per sample.
- Staging recovery scans only `Corpus\.staging`.
- No full corpus rescan occurs for each sample.
- No sample is loaded entirely into memory.
- No sample is executed.
