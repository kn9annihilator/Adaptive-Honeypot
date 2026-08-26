# Graph Report - Codebase  (2026-08-27)

## Corpus Check
- 4 files · ~962 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 21 nodes · 22 edges · 6 communities (3 shown, 3 thin omitted)
- Extraction: 100% EXTRACTED · 0% INFERRED · 0% AMBIGUOUS
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `d2c51f94`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- Malware & Ransomware Family Classification Pipeline
- build_manifest.py
- main
- rules/graphify.md
- workflows/graphify.md
- write_manifest

## God Nodes (most connected - your core abstractions)
1. `main()` - 5 edges
2. `build_rows()` - 4 edges
3. `Malware & Ransomware Family Classification Pipeline` - 4 edges
4. `load_api_key()` - 3 edges
5. `query_malwarebazaar()` - 3 edges
6. `is_pe_candidate()` - 3 edges
7. `write_manifest()` - 3 edges
8. `Load the MalwareBazaar Auth-Key from .env.` - 1 edges
9. `Query MalwareBazaar metadata only.` - 1 edges
10. `Keep PE executables and DLLs for the initial corpus.` - 1 edges

## Surprising Connections (you probably didn't know these)
- `main()` --calls--> `build_rows()`  [EXTRACTED]
  tools/build_manifest.py → tools/build_manifest.py  _Bridges community 1 → community 2_
- `main()` --calls--> `write_manifest()`  [EXTRACTED]
  tools/build_manifest.py → tools/build_manifest.py  _Bridges community 5 → community 2_

## Import Cycles
- None detected.

## Communities (6 total, 3 thin omitted)

### Community 0 - "Malware & Ransomware Family Classification Pipeline"
Cohesion: 0.40
Nodes (4): Architecture, Malware & Ransomware Family Classification Pipeline, Motivation, Overview

### Community 1 - "build_manifest.py"
Cohesion: 0.50
Nodes (4): build_rows(), is_pe_candidate(), Keep PE executables and DLLs for the initial corpus., Convert MalwareBazaar records into our manifest schema.

### Community 2 - "main"
Cohesion: 0.40
Nodes (5): load_api_key(), main(), query_malwarebazaar(), Load the MalwareBazaar Auth-Key from .env., Query MalwareBazaar metadata only.

## Knowledge Gaps
- **5 isolated node(s):** `graphify`, `Workflow: graphify`, `Overview`, `Motivation`, `Architecture`
  These have ≤1 connection - possible missing edges or undocumented components.
- **3 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `main()` connect `main` to `build_manifest.py`, `write_manifest`?**
  _High betweenness centrality (0.063) - this node is a cross-community bridge._
- **Why does `build_rows()` connect `build_manifest.py` to `main`?**
  _High betweenness centrality (0.058) - this node is a cross-community bridge._
- **Why does `load_api_key()` connect `main` to `build_manifest.py`?**
  _High betweenness centrality (0.053) - this node is a cross-community bridge._
- **What connects `graphify`, `Workflow: graphify`, `Overview` to the rest of the system?**
  _5 weakly-connected nodes found - possible documentation gaps or missing edges._