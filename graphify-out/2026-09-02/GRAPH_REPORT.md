# Graph Report - Codebase  (2026-09-02)

## Corpus Check
- 11 files · ~6,899 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 140 nodes · 253 edges · 12 communities (10 shown, 2 thin omitted)
- Extraction: 96% EXTRACTED · 4% INFERRED · 0% AMBIGUOUS · INFERRED: 9 edges (avg confidence: 0.89)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `8cf83559`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- Malware & Ransomware Family Classification Pipeline
- build_manifest.py
- corpus_manifest.py
- rules/graphify.md
- workflows/graphify.md
- validate_record
- family_availability.py
- acquire_samples.py
- Corpus Acquisition v3
- sha256_file
- AcquisitionV32Tests
- family_temporal_audit.py

## God Nodes (most connected - your core abstractions)
1. `validate_record()` - 20 edges
2. `ManifestTests` - 16 edges
3. `AcquisitionV32Tests` - 15 edges
4. `acquire()` - 14 edges
5. `ManifestValidationError` - 12 edges
6. `JsonlManifestWriter` - 12 edges
7. `make_record()` - 12 edges
8. `recover_orphans()` - 10 edges
9. `new_record()` - 9 edges
10. `_hash()` - 8 edges

## Surprising Connections (you probably didn't know these)
- `ManifestTests` --uses--> `ManifestValidationError`  [INFERRED]
  tools/test_corpus_manifest.py → tools/corpus_manifest.py
- `ManifestTests` --uses--> `CorpusIdentityIndex`  [INFERRED]
  tools/test_corpus_manifest.py → tools/corpus_manifest.py
- `recover_orphans()` --calls--> `JsonlManifestWriter`  [EXTRACTED]
  tools/acquire_samples.py → tools/corpus_manifest.py
- `acquire()` --calls--> `JsonlManifestWriter`  [EXTRACTED]
  tools/acquire_samples.py → tools/corpus_manifest.py
- `ManifestTests` --uses--> `DuplicateSampleError`  [INFERRED]
  tools/test_corpus_manifest.py → tools/corpus_manifest.py

## Import Cycles
- None detected.

## Communities (12 total, 2 thin omitted)

### Community 0 - "Malware & Ransomware Family Classification Pipeline"
Cohesion: 0.40
Nodes (4): Architecture, Malware & Ransomware Family Classification Pipeline, Motivation, Overview

### Community 1 - "build_manifest.py"
Cohesion: 0.24
Nodes (11): build_rows(), is_pe_candidate(), load_api_key(), main(), query_malwarebazaar(), Write the candidate manifest CSV., Load the MalwareBazaar Auth-Key from .env., Query MalwareBazaar metadata only. (+3 more)

### Community 2 - "corpus_manifest.py"
Cohesion: 0.20
Nodes (13): Any, Pattern, CorpusIdentityIndex, _hash(), ManifestError, ManifestValidationError, _mapping(), _optional_string() (+5 more)

### Community 5 - "validate_record"
Cohesion: 0.23
Nodes (8): DuplicateSampleError, JsonlManifestWriter, Raised when a sample already exists in the manifest., Validate and normalize one manifest record. The caller's object is never…, Append-only JSONL writer with validation and O(1) duplicate detection., validate_record(), make_record(), ManifestTests

### Community 6 - "family_availability.py"
Cohesion: 0.52
Nodes (6): analyse_family(), is_pe(), load_api_key(), main(), parse_date(), query_family()

### Community 7 - "acquire_samples.py"
Cohesion: 0.12
Nodes (29): acquire(), AcquisitionStats, build_record(), candidate_is_valid(), CorpusIdentityIndex, download_archive(), extract_sample(), load_api_key() (+21 more)

### Community 8 - "Corpus Acquisition v3"
Cohesion: 0.22
Nodes (8): Acquisition lifecycle, Candidate validation, Corpus Acquisition v3, Integrity, MalwareBazaar transport, Performance, Placement, Storage/recovery

### Community 9 - "sha256_file"
Cohesion: 0.40
Nodes (3): Path, Calculate SHA-256 using bounded memory., sha256_file()

### Community 10 - "AcquisitionV32Tests"
Cohesion: 0.11
Nodes (4): new_record(), Return the current UTC time as RFC-3339 with Z suffix., utc_now(), AcquisitionV32Tests

### Community 11 - "family_temporal_audit.py"
Cohesion: 0.52
Nodes (6): analyse(), is_pe(), load_api_key(), main(), parse_date(), query_family()

## Knowledge Gaps
- **12 isolated node(s):** `graphify`, `Workflow: graphify`, `Overview`, `Motivation`, `Architecture` (+7 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **2 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `JsonlManifestWriter` connect `validate_record` to `sha256_file`, `corpus_manifest.py`, `acquire_samples.py`?**
  _High betweenness centrality (0.142) - this node is a cross-community bridge._
- **Why does `new_record()` connect `AcquisitionV32Tests` to `corpus_manifest.py`, `validate_record`?**
  _High betweenness centrality (0.080) - this node is a cross-community bridge._
- **Are the 4 inferred relationships involving `ManifestTests` (e.g. with `CorpusIdentityIndex` and `DuplicateSampleError`) actually correct?**
  _`ManifestTests` has 4 INFERRED edges - model-reasoned connections that need verification._
- **What connects `graphify`, `Workflow: graphify`, `Overview` to the rest of the system?**
  _12 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `acquire_samples.py` be split into smaller, more focused modules?**
  _Cohesion score 0.12121212121212122 - nodes in this community are weakly interconnected._
- **Should `AcquisitionV32Tests` be split into smaller, more focused modules?**
  _Cohesion score 0.1111111111111111 - nodes in this community are weakly interconnected._