# Graph Report - Codebase  (2026-09-14)

## Corpus Check
- 21 files · ~13,038 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 200 nodes · 344 edges · 17 communities (14 shown, 3 thin omitted)
- Extraction: 97% EXTRACTED · 3% INFERRED · 0% AMBIGUOUS · INFERRED: 10 edges (avg confidence: 0.89)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `28ceaf6c`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- Malware & Ransomware Family Classification Pipeline
- build_manifest.py
- research_acquisition_plan_v2.py
- rules/graphify.md
- workflows/graphify.md
- validate_record
- family_availability.py
- acquire_samples.py
- Corpus Acquisition v3
- family_metadata_quality.py
- AcquisitionV32Tests
- family_temporal_audit.py
- family_label_audit.py
- research_acquisition_plan.py

## God Nodes (most connected - your core abstractions)
1. `validate_record()` - 20 edges
2. `ManifestTests` - 16 edges
3. `AcquisitionV32Tests` - 15 edges
4. `acquire()` - 14 edges
5. `ManifestValidationError` - 12 edges
6. `JsonlManifestWriter` - 12 edges
7. `make_record()` - 12 edges
8. `recover_orphans()` - 10 edges
9. `main()` - 10 edges
10. `new_record()` - 9 edges

## Surprising Connections (you probably didn't know these)
- `recover_orphans()` --calls--> `JsonlManifestWriter`  [EXTRACTED]
  tools/acquire_samples.py → tools/corpus_manifest.py
- `acquire()` --calls--> `JsonlManifestWriter`  [EXTRACTED]
  tools/acquire_samples.py → tools/corpus_manifest.py
- `ManifestTests` --uses--> `ManifestValidationError`  [INFERRED]
  tools/test_corpus_manifest.py → tools/corpus_manifest.py
- `ManifestTests` --uses--> `DuplicateSampleError`  [INFERRED]
  tools/test_corpus_manifest.py → tools/corpus_manifest.py
- `ManifestTests` --uses--> `CorpusIdentityIndex`  [INFERRED]
  tools/test_corpus_manifest.py → tools/corpus_manifest.py

## Import Cycles
- None detected.

## Communities (17 total, 3 thin omitted)

### Community 0 - "Malware & Ransomware Family Classification Pipeline"
Cohesion: 0.40
Nodes (4): Architecture, Malware & Ransomware Family Classification Pipeline, Motivation, Overview

### Community 1 - "build_manifest.py"
Cohesion: 0.24
Nodes (11): build_rows(), is_pe_candidate(), load_api_key(), main(), query_malwarebazaar(), Write the candidate manifest CSV., Load the MalwareBazaar Auth-Key from .env., Query MalwareBazaar metadata only. (+3 more)

### Community 2 - "research_acquisition_plan_v2.py"
Cohesion: 0.11
Nodes (27): is_pe_candidate(), is_valid_sha256(), load_api_key(), load_existing_corpus_hashes(), load_v1_family_candidates(), main(), normalize_candidate(), parse_first_seen() (+19 more)

### Community 5 - "validate_record"
Cohesion: 0.11
Nodes (27): Any, Pattern, CorpusIdentityIndex, DuplicateSampleError, _hash(), JsonlManifestWriter, ManifestError, ManifestValidationError (+19 more)

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
Nodes (13): is_pe_candidate(), is_valid_sha256(), load_api_key(), load_existing_corpus_hashes(), main(), normalize_candidate(), parse_first_seen(), Counter (+5 more)

## Knowledge Gaps
- **12 isolated node(s):** `graphify`, `Workflow: graphify`, `Overview`, `Motivation`, `Architecture` (+7 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **3 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `JsonlManifestWriter` connect `validate_record` to `acquire_samples.py`?**
  _High betweenness centrality (0.070) - this node is a cross-community bridge._
- **Why does `new_record()` connect `validate_record` to `AcquisitionV32Tests`?**
  _High betweenness centrality (0.039) - this node is a cross-community bridge._
- **Are the 4 inferred relationships involving `ManifestTests` (e.g. with `CorpusIdentityIndex` and `DuplicateSampleError`) actually correct?**
  _`ManifestTests` has 4 INFERRED edges - model-reasoned connections that need verification._
- **What connects `graphify`, `Workflow: graphify`, `Overview` to the rest of the system?**
  _12 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `research_acquisition_plan_v2.py` be split into smaller, more focused modules?**
  _Cohesion score 0.1111111111111111 - nodes in this community are weakly interconnected._
- **Should `validate_record` be split into smaller, more focused modules?**
  _Cohesion score 0.10628019323671498 - nodes in this community are weakly interconnected._
- **Should `acquire_samples.py` be split into smaller, more focused modules?**
  _Cohesion score 0.1111111111111111 - nodes in this community are weakly interconnected._