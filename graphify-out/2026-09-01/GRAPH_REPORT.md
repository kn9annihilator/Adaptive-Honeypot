# Graph Report - Codebase  (2026-08-27)

## Corpus Check
- 9 files · ~3,763 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 102 nodes · 200 edges · 11 communities (8 shown, 3 thin omitted)
- Extraction: 98% EXTRACTED · 2% INFERRED · 0% AMBIGUOUS · INFERRED: 5 edges (avg confidence: 0.95)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `f598228d`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- Malware & Ransomware Family Classification Pipeline
- build_manifest.py
- validate_record
- rules/graphify.md
- workflows/graphify.md
- ManifestTests
- AcquisitionTests
- acquire_samples.py
- Corpus Manifest / Acquisition v2
- CorpusIdentityIndex
- CorpusIdentityIndex

## God Nodes (most connected - your core abstractions)
1. `validate_record()` - 20 edges
2. `ManifestTests` - 16 edges
3. `acquire()` - 12 edges
4. `make_record()` - 12 edges
5. `ManifestValidationError` - 11 edges
6. `JsonlManifestWriter` - 11 edges
7. `CorpusIdentityIndex` - 9 edges
8. `_hash()` - 8 edges
9. `CorpusIdentityIndex` - 8 edges
10. `AcquisitionTests` - 8 edges

## Surprising Connections (you probably didn't know these)
- `AcquisitionTests` --uses--> `CorpusIdentityIndex`  [INFERRED]
  tools/test_acquire_samples.py → tools/acquire_samples.py
- `ManifestTests` --uses--> `ManifestValidationError`  [INFERRED]
  tools/test_corpus_manifest.py → tools/corpus_manifest.py
- `ManifestTests` --uses--> `DuplicateSampleError`  [INFERRED]
  tools/test_corpus_manifest.py → tools/corpus_manifest.py
- `ManifestTests` --uses--> `CorpusIdentityIndex`  [INFERRED]
  tools/test_corpus_manifest.py → tools/corpus_manifest.py
- `acquire()` --calls--> `JsonlManifestWriter`  [EXTRACTED]
  tools/acquire_samples.py → tools/corpus_manifest.py

## Import Cycles
- None detected.

## Communities (11 total, 3 thin omitted)

### Community 0 - "Malware & Ransomware Family Classification Pipeline"
Cohesion: 0.40
Nodes (4): Architecture, Malware & Ransomware Family Classification Pipeline, Motivation, Overview

### Community 1 - "build_manifest.py"
Cohesion: 0.24
Nodes (11): build_rows(), is_pe_candidate(), load_api_key(), main(), query_malwarebazaar(), Write the candidate manifest CSV., Load the MalwareBazaar Auth-Key from .env., Query MalwareBazaar metadata only. (+3 more)

### Community 2 - "validate_record"
Cohesion: 0.24
Nodes (17): Any, Pattern, DuplicateSampleError, _hash(), ManifestError, ManifestValidationError, _mapping(), new_record() (+9 more)

### Community 5 - "ManifestTests"
Cohesion: 0.27
Nodes (4): JsonlManifestWriter, Append-only JSONL writer with validation and O(1) duplicate detection., make_record(), ManifestTests

### Community 6 - "AcquisitionTests"
Cohesion: 0.22
Nodes (6): candidate_is_valid(), Candidate-stage validation. IMPORTANT: rejection here is a research-…, Remove only abandoned staging data; canonical samples are never deleted here., recover_staging(), valid_sha256(), AcquisitionTests

### Community 7 - "acquire_samples.py"
Cohesion: 0.44
Nodes (10): acquire(), build_record(), download_sample(), load_api_key(), log_event(), main(), Path, sha256_file() (+2 more)

### Community 8 - "Corpus Manifest / Acquisition v2"
Cohesion: 0.22
Nodes (8): 1. Candidate validation, 2. Cryptographic verification, Acquisition model, Corpus Manifest / Acquisition v2, Performance properties, Placement, Storage transaction, Two validation boundaries

### Community 9 - "CorpusIdentityIndex"
Cohesion: 0.29
Nodes (3): CorpusIdentityIndex, Path, One-pass manifest index; membership checks are O(1).

## Knowledge Gaps
- **11 isolated node(s):** `graphify`, `Workflow: graphify`, `Overview`, `Motivation`, `Architecture` (+6 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **3 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `JsonlManifestWriter` connect `ManifestTests` to `CorpusIdentityIndex`, `validate_record`, `acquire_samples.py`?**
  _High betweenness centrality (0.263) - this node is a cross-community bridge._
- **Why does `acquire()` connect `acquire_samples.py` to `CorpusIdentityIndex`, `ManifestTests`, `AcquisitionTests`?**
  _High betweenness centrality (0.110) - this node is a cross-community bridge._
- **Why does `ManifestTests` connect `ManifestTests` to `CorpusIdentityIndex`, `validate_record`?**
  _High betweenness centrality (0.092) - this node is a cross-community bridge._
- **Are the 4 inferred relationships involving `ManifestTests` (e.g. with `CorpusIdentityIndex` and `DuplicateSampleError`) actually correct?**
  _`ManifestTests` has 4 INFERRED edges - model-reasoned connections that need verification._
- **What connects `graphify`, `Workflow: graphify`, `Overview` to the rest of the system?**
  _11 weakly-connected nodes found - possible documentation gaps or missing edges._