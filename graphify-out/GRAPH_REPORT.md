# Graph Report - Codebase  (2026-11-04)

## Corpus Check
- 38 files · ~27,724 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 329 nodes · 510 edges · 31 communities (28 shown, 3 thin omitted)
- Extraction: 96% EXTRACTED · 4% INFERRED · 0% AMBIGUOUS · INFERRED: 20 edges (avg confidence: 0.87)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `c2955231`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- Adaptive-Honeypot
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
- ValueError
- run_mlp_static.py
- extract_features
- run_mlp_pe_api.py
- run_mlp_pe_dll.py
- build_tfidf_features.py
- main
- build_pe_features.py
- run_rf_tuning.py
- run_xgb_tuning.py

## God Nodes (most connected - your core abstractions)
1. `validate_record()` - 20 edges
2. `Adaptive-Honeypot` - 18 edges
3. `ManifestTests` - 16 edges
4. `AcquisitionV32Tests` - 15 edges
5. `acquire()` - 14 edges
6. `ManifestValidationError` - 12 edges
7. `JsonlManifestWriter` - 12 edges
8. `make_record()` - 12 edges
9. `recover_orphans()` - 10 edges
10. `main()` - 10 edges

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

## Communities (31 total, 3 thin omitted)

### Community 0 - "Adaptive-Honeypot"
Cohesion: 0.06
Nodes (31): 1. Malware Acquisition and Corpus Construction, 2. Static Malware Analysis, 3. Feature Engineering, 4. Dataset Partitioning, 5. Machine-Learning Models, 6. Dynamic Analysis — Ongoing, Acknowledgements, Adaptive-Honeypot (+23 more)

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
Cohesion: 0.12
Nodes (28): acquire(), AcquisitionStats, build_record(), candidate_is_valid(), CorpusIdentityIndex, download_archive(), extract_sample(), load_api_key() (+20 more)

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

### Community 17 - "ValueError"
Cohesion: 0.10
Nodes (27): load_matrix(), main(), count_trainable_parameters(), create_dataloaders(), create_label_mapping(), encode_labels(), evaluate_model(), find_column() (+19 more)

### Community 18 - "run_mlp_static.py"
Cohesion: 0.18
Nodes (9): ndarray, calculate_metrics(), evaluate(), load_features(), no_grad, Path, Load sparse NPZ feature matrix and convert to float32 dense array. PE…, StaticMLP (+1 more)

### Community 19 - "extract_features"
Cohesion: 0.24
Nodes (12): decode_bytes(), extract_features(), main(), Path, Calculate Shannon entropy for a byte sequence., Calculate SHA-256 of a file., Extract executable/readable/writable section flags., Safely decode PE byte strings. (+4 more)

### Community 20 - "run_mlp_pe_api.py"
Cohesion: 0.28
Nodes (5): calculate_metrics(), evaluate(), no_grad, StaticMLP, train_one_epoch()

### Community 21 - "run_mlp_pe_dll.py"
Cohesion: 0.28
Nodes (5): calculate_metrics(), evaluate(), no_grad, StaticMLP, train_one_epoch()

### Community 22 - "build_tfidf_features.py"
Cohesion: 0.52
Nodes (6): build_vectorizer(), load_split(), main(), process_feature(), save_matrix(), tokenize_imports()

### Community 23 - "main"
Cohesion: 0.60
Nodes (5): build_models(), evaluate(), load_labels(), load_representation(), main()

### Community 24 - "build_pe_features.py"
Cohesion: 0.83
Nodes (3): load_split(), main(), save_matrix()

### Community 25 - "run_rf_tuning.py"
Cohesion: 0.83
Nodes (3): evaluate_configuration(), load_labels(), main()

### Community 26 - "run_xgb_tuning.py"
Cohesion: 0.83
Nodes (3): evaluate_configuration(), load_labels(), main()

## Knowledge Gaps
- **36 isolated node(s):** `graphify`, `Workflow: graphify`, `Windows Malware Family Classification Using Machine Learning and Deep Learning`, `Overview`, `Research Objectives` (+31 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **3 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `JsonlManifestWriter` connect `validate_record` to `acquire_samples.py`?**
  _High betweenness centrality (0.032) - this node is a cross-community bridge._
- **Why does `extract_features()` connect `extract_features` to `ValueError`?**
  _High betweenness centrality (0.031) - this node is a cross-community bridge._
- **Are the 15 inferred relationships involving `ValueError` (e.g. with `main()` and `extract_features()`) actually correct?**
  _`ValueError` has 15 INFERRED edges - model-reasoned connections that need verification._
- **Are the 4 inferred relationships involving `ManifestTests` (e.g. with `CorpusIdentityIndex` and `DuplicateSampleError`) actually correct?**
  _`ManifestTests` has 4 INFERRED edges - model-reasoned connections that need verification._
- **What connects `graphify`, `Workflow: graphify`, `Windows Malware Family Classification Using Machine Learning and Deep Learning` to the rest of the system?**
  _36 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Adaptive-Honeypot` be split into smaller, more focused modules?**
  _Cohesion score 0.0625 - nodes in this community are weakly interconnected._
- **Should `research_acquisition_plan_v2.py` be split into smaller, more focused modules?**
  _Cohesion score 0.1111111111111111 - nodes in this community are weakly interconnected._