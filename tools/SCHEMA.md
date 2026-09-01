# Corpus Acquisition v3

## Placement

Put these in `D:\Honeypot\Codebase\tools\`:

- `acquire_samples.py`
- `test_acquire_samples.py`
- `reconcile_corpus.py` is not required in v3; reconciliation is exposed by `acquire_samples.py --reconcile`.
- `SCHEMA.md`

Keep `build_manifest.py` unchanged.

## MalwareBazaar transport

`get_file` returns a password-protected ZIP. MalwareBazaar documents AES-128 encryption with password `infected`; `pyzipper` is required for AES extraction.

The transport ZIP is never hashed as the malware identity. The extracted member is the artifact whose SHA-256 must equal the expected MalwareBazaar SHA-256.

## Acquisition lifecycle

`candidate -> queued -> download_started -> download_completed -> archive_validation -> archive_extracted -> cryptographic_verification -> cryptographically_verified -> storage_started -> stored -> ready_for_analysis`

Failure/alternate states:

- `candidate_rejected`
- `duplicate`
- `archive_validation_failed`
- `integrity_failed`
- `download_failed`
- `storage_failed`

## Candidate validation

Candidate validation happens before network acquisition.

IMPORTANT: rejection at this boundary is a scope/metadata decision during the validation period, NOT a cryptographic-integrity rejection.

## Integrity

The extracted sample is hashed once before canonical storage.

After the atomic staging-to-quarantine rename, the final canonical sample is hashed again. The final hash must equal the expected SHA-256 and the pre-commit calculated SHA-256.

## Storage/recovery

Downloads and extracted artifacts live temporarily under:

`Corpus\.staging\<transaction>\`

The canonical sample is:

`Corpus\samples\quarantine\<SHA256>\sample`

The staging directory is renamed atomically on the same filesystem.

If JSONL persistence fails after canonical storage, the verified sample is retained rather than deleted. Run:

`python acquire_samples.py --reconcile`

to detect:

- canonical samples missing from `samples.jsonl`
- manifest records whose canonical sample is missing

Reconciliation is check-only and does not mutate evidence.

## Performance

- 1 MiB streaming I/O for download, extraction, and hashing.
- No full sample is loaded into RAM.
- Candidate manifest is read once.
- Corpus identity is scanned once.
- JSONL writer is opened once per acquisition run.
- Reconciliation scans only the manifest and canonical quarantine tree.
- No polling, sleeps, or per-sample corpus rescans.
