# Malware & Ransomware Family Classification Pipeline

[![Status](https://img.shields.io/badge/status-work--in--progress-yellow)](https://github.com/)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-TBD-lightgrey)](LICENSE)
[![Research](https://img.shields.io/badge/type-cybersecurity%20research-red)](https://github.com/)
[![ML/DL](https://img.shields.io/badge/ML%2FDL-family%20classification-purple)](https://github.com/)

> **Final Year Major Project** — Honeypot-based malware capture, family classification, and adversarial robustness evaluation.

---

## Overview

This project implements a **honeypot-based capture pipeline** for malware and ransomware samples, followed by a three-track family classification system:

1. **Manual Reverse Engineering**
   - Static and dynamic analysis of captured binaries.
   - Establishes ground-truth malware family labels.

2. **Passive Classification**
   - Automated static feature extraction:
     - PE headers
     - Imphash
     - Section entropy
   - OSINT correlation using:
     - VirusTotal
     - MalwareBazaar
   - Samples with existing public intelligence are labeled directly.

3. **Active Classification**
   - ML/DL-based family classification for novel or unseen samples.
   - Uses static and behavioral features extracted from sandboxed detonation.

The system is evaluated for **robustness against known malware evasion techniques**, including:

- I/O operation disguising
- Intermittent encryption
- Other published adversarial/evasion techniques

The evaluation focuses on classification robustness against adversarial behavior rather than reporting accuracy on clean samples alone.

---

## Motivation

Traditional **signature- and hash-based detection** approaches are ineffective against:

- Repacked malware
- Modified variants
- Previously unseen binaries
- Polymorphic or behaviorally modified samples

Family classification based on **static and behavioral patterns** can generalize across variants belonging to the same malware family, even when the exact binary has never previously been observed.

Most existing honeypot and malware-detection research focuses on single-layer detection using non-adversarial samples.

This project instead focuses on:

- Multi-stage malware classification
- Ground-truth labeling through manual RE
- Static feature-based classification
- Behavioral ML/DL classification
- Robustness against published evasion techniques

---

## Architecture

```text
                    ┌──────────────────────────────┐
                    │    Honeypot Capture Layer    │
                    │   Dionaea + Samba-bait       │
                    └──────────────┬───────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────────┐
                    │        Sample Triage         │
                    └──────────────┬───────────────┘
                                   │
                         ┌─────────┴─────────┐
                         ▼                   ▼
              ┌──────────────────┐   ┌──────────────────────┐
              │   Manual RE      │   │   Passive Lookup     │
              │ Static + Dynamic │   │ VT / MalwareBazaar   │
              └────────┬─────────┘   └──────────┬───────────┘
                       │                        │
                       │                 ┌──────┴──────┐
                       │                 │             │
                       │                Hit           Miss
                       │                 │             │
                       │                 ▼             ▼
                       │            Labeled Sample    Active
                       │                              Classification
                       │                               │
                       │                               ▼
                       │                    Static + Behavioral
                       │                         ML / DL
                       │                               │
                       └───────────────┬───────────────┘
                                       ▼
                            ┌────────────────────────┐
                            │    Labeled Dataset     │
                            └────────────┬───────────┘
                                         │
                                         ▼
                            ┌────────────────────────┐
                            │ Model Training &       │
                            │ Evaluation             │
                            └────────────┬───────────┘
                                         │
                                         ▼
                            ┌────────────────────────┐
                            │   Evasion Testing &    │
                            │ Robustness Evaluation  │
                            └────────────────────────┘