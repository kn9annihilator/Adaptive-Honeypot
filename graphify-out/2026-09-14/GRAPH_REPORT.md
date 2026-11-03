# Graph Report - Codebase  (2026-09-05)

## Corpus Check
- 16 files · ~10,120 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 169 nodes · 309 edges · 17 communities (14 shown, 3 thin omitted)
- Extraction: 96% EXTRACTED · 4% INFERRED · 0% AMBIGUOUS · INFERRED: 13 edges (avg confidence: 0.88)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `65cc0aa8`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- Malware & Ransomware Family Classification Pipeline
- build_manifest.py
- CorpusIdentityIndex
- rules/graphify.md
- workflows/graphify.md
- ManifestTests
- family_availability.py
- acquire_samples.py
- Corpus Acquisition v3
- family_metadata_quality.py
- AcquisitionV32Tests
- family_temporal_audit.py
- family_label_audit.py
- research_acquisition_plan.py
- validate_record
- corpus_manifest.py
- sha256_file

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
10. `main()` - 9 edges

## Surprising Connections (you probably didn't know these)
- `ManifestTests` --uses--> `ManifestValidationError`  [INFERRED]
  tools/test_corpus_manifest.py → tools/corpus_manifest.py
- `ManifestTests` --uses--> `DuplicateSampleError`  [INFERRED]
  tools/test_corpus_manifest.py → tools/corpus_manifest.py
- `ManifestTests` --uses--> `CorpusIdentityIndex`  [INFERRED]
  tools/test_corpus_manifest.py → tools/corpus_manifest.py
- `recover_orphans()` --calls--> `JsonlManifestWriter`  [EXTRACTED]
  tools/acquire_samples.py → tools/corpus_manifest.py
- `acquire()` --calls--> `JsonlManifestWriter`  [EXTRACTED]
  tools/acquire_samples.py → tools/corpus_manifest.py

## Import Cycles
- None detected.

## Communities (17 total, 3 thin omitted)

### Community 0 - "Malware & Ransomware Family Classification Pipeline"
Cohesion: 0.40
Nodes (4): Architecture, Malware & Ransomware Family Classification Pipeline, Motivation, Overview

### Community 1 - "build_manifest.py"
Cohesion: 0.24
Nodes (11): build_rows(), is_pe_candidate(), load_api_key(), main(), query_malwarebazaar(), Write the candidate manifest CSV., Load the MalwareBazaar Auth-Key from .env., Query MalwareBazaar metadata only. (+3 more)

### Community 2 - "CorpusIdentityIndex"
Cohesion: 0.32
Nodes (4): Pattern, CorpusIdentityIndex, _hash(), One-pass manifest index; membership checks are O(1).

### Community 5 - "ManifestTests"
Cohesion: 0.27
Nodes (4): JsonlManifestWriter, Append-only JSONL writer with validation and O(1) duplicate detection., make_record(), ManifestTests

### Community 6 - "family_availability.py"
Cohesion: 0.52
Nodes (6): analyse_family(), is_pe(), load_api_key(), main(), parse_date(), query_family()

### Community 7 - "acquire_samples.py"
Cohesion: 0.11
Nodes (30): acquire(), AcquisitionStats, build_record(), candidate_is_valid(), CorpusIdentityIndex, download_archive(), extract_sample(), load_api_key() (+22 more)

### Community 8 - "Corpus Acquisition v3"
Cohesion: 0.22
Nodes (8): Acquisition lifecycle, Candidate validation, Corpus Acquisition v3, Integrity, MalwareBazaar transport, Performance, Placement, Storage/recovery

### Community 9 - "family_metadata_quality.py"
Cohesion: 0.52
Nodes (6): analyse(), is_pe(), load_api_key(), main(), present(), query_family()

### Community 11 - "family_temporal_audit.py"
Cohesion: 0.52
Nodes (6): analyse(), is_pe(), load_api_key(), main(), parse_date(), query_family()

### Community 12 - "family_label_audit.py"
Cohesion: 0.60
Nodes (5): analyse(), is_pe(), load_api_key(), main(), query_family()

### Community 13 - "research_acquisition_plan.py"
Cohesion: 0.30
Nodes (13): Counter, datetime, is_pe_candidate(), is_valid_sha256(), load_api_key(), load_existing_corpus_hashes(), main(), normalize_candidate() (+5 more)

### Community 14 - "validate_record"
Cohesion: 0.40
Nodes (9): Any, ManifestValidationError, _mapping(), _optional_string(), Raised when a manifest record violates the schema., Validate and normalize one manifest record. The caller's object is never…, _required(), _timestamp() (+1 more)

### Community 15 - "corpus_manifest.py"
Cohesion: 0.33
Nodes (7): DuplicateSampleError, ManifestError, new_record(), Corpus manifest schema, validator, identity index, and JSONL writer., Raised when a sample already exists in the manifest., Return the current UTC time as RFC-3339 with Z suffix., utc_now()

### Community 16 - "sha256_file"
Cohesion: 0.40
Nodes (3): Path, Calculate SHA-256 using bounded memory., sha256_file()

## Knowledge Gaps
- **12 isolated node(s):** `graphify`, `Workflow: graphify`, `Overview`, `Motivation`, `Architecture` (+7 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **3 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `JsonlManifestWriter` connect `ManifestTests` to `sha256_file`, `corpus_manifest.py`, `validate_record`, `acquire_samples.py`?**
  _High betweenness centrality (0.104) - this node is a cross-community bridge._
- **Why does `new_record()` connect `corpus_manifest.py` to `CorpusIdentityIndex`, `AcquisitionV32Tests`, `ManifestTests`, `validate_record`?**
  _High betweenness centrality (0.058) - this node is a cross-community bridge._
- **Are the 4 inferred relationships involving `ManifestTests` (e.g. with `CorpusIdentityIndex` and `DuplicateSampleError`) actually correct?**
  _`ManifestTests` has 4 INFERRED edges - model-reasoned connections that need verification._
- **What connects `graphify`, `Workflow: graphify`, `Overview` to the rest of the system?**
  _12 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `acquire_samples.py` be split into smaller, more focused modules?**
  _Cohesion score 0.1111111111111111 - nodes in this community are weakly interconnected._
- **Should `AcquisitionV32Tests` be split into smaller, more focused modules?**
  _Cohesion score 0.125 - nodes in this community are weakly interconnected._