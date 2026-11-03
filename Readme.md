# Adaptive-Honeypot
### Windows Malware Family Classification Using Machine Learning and Deep Learning

<p align="center">
  <img src="https://img.shields.io/badge/Project-Research%20%26%20Development-181717?style=for-the-badge&logo=github" />
  <img src="https://img.shields.io/badge/Domain-Cybersecurity-0A66C2?style=for-the-badge&logo=hackthebox&logoColor=white" />
  <img src="https://img.shields.io/badge/Language-Python-3776AB?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/Status-Work%20in%20Progress-orange?style=for-the-badge" />
</p>

<p align="center">
  <strong>Beyond Detection: Learning the Family of Malware Using Machine Learning and Deep Learning</strong>
</p>

<p align="center">
  <a href="#overview">Overview</a> •
  <a href="#research-objectives">Objectives</a> •
  <a href="#system-methodology">Methodology</a> •
  <a href="#experimental-results">Results</a> •
  <a href="#repository-structure">Structure</a> •
  <a href="#roadmap">Roadmap</a>
</p>

---

## Overview

**Adaptive-Honeypot** is an ongoing cybersecurity research project investigating automated Windows malware-family classification using static analysis, machine learning (ML), and deep learning (DL).

The research focuses on identifying the malware family associated with a given executable rather than performing conventional binary malware detection. Instead of determining only whether a file is malicious or benign, the classification framework attempts to assign a malicious executable to one of several predefined malware families.

The project investigates the effectiveness of different static feature representations, including:

- Portable Executable (PE) metadata.
- Dynamic-Link Library (DLL) imports.
- Application Programming Interface (API) imports.
- Combined static feature representations.

These representations are evaluated using classical machine-learning algorithms and neural-network architectures.

The broader project also incorporates honeypot infrastructure and malware acquisition workflows to support malware collection, operational validation, and future behavioral analysis.

**Current research focus:** Static Windows malware-family classification.

**Development status:** Active development. Dynamic behavioral classification and additional research components remain ongoing.

## Research Objectives

The primary objective is to investigate how effectively static executable characteristics can distinguish between different Windows malware families.

The research is organized around the following objectives:

1. **Malware Acquisition:** Establish a structured malware corpus with traceable sample identities and source metadata.
2. **Static Analysis:** Extract structural PE characteristics and imported library/API information.
3. **Feature Engineering:** Construct numerical and TF-IDF-based feature representations.
4. **Model Evaluation:** Evaluate classical machine-learning and neural-network classifiers.
5. **Performance Analysis:** Compare feature representations using validation and held-out test metrics.
6. **Behavioral Analysis:** Extend the research toward dynamic feature collection and sequential behavioral classification.

## Research Scope

The current classification experiments cover the following twelve Windows malware families:

| No. | Malware Family |
|---:|---|
| 1 | AgentTesla |
| 2 | AsyncRAT |
| 3 | BitRAT |
| 4 | DarkComet |
| 5 | Dridex |
| 6 | Emotet |
| 7 | FormBook |
| 8 | IcedID |
| 9 | NanoCore |
| 10 | njRAT |
| 11 | TrickBot |
| 12 | XWorm |

The dataset labels originate from MalwareBazaar metadata and tags. They are treated as source-provided labels rather than independently verified ground truth.

## System Methodology

The research workflow is divided into multiple stages.

### 1. Malware Acquisition and Corpus Construction

Malware samples are acquired using MalwareBazaar metadata and an organized acquisition workflow.

The acquisition process includes:

- Candidate manifest preparation and filtering.
- SHA-256 identity generation and verification.
- Malware sample retrieval.
- Integrity verification.
- Canonical corpus storage.
- Dataset reconciliation.

The corpus contains 1,620 unique acquired SHA-256 identities. Following removal of one empty object and exclusion of one malformed PE sample, 1,618 structurally usable PE samples remained for classification experiments.

SHA-256 is used for byte-level identity verification and integrity tracking.

### 2. Static Malware Analysis

Static analysis is performed on Windows Portable Executable files without requiring execution of the samples.

Three principal feature groups are extracted.

**A. PE Metadata**

Structural and numerical characteristics of PE files, including:

- File size.
- Number of sections.
- PE characteristics.
- Entry point.
- Image base.
- Image and header sizes.
- Subsystem and DLL characteristics.
- Section permissions and sizes.
- Section entropy statistics.
- Imported DLL and API counts.
- Architecture indicators.

The resulting PE representation contains 22 features.

**B. DLL Imports**

Imported dynamic-link libraries are represented using TF-IDF encoding.

- Vocabulary size: 78.
- Representation: DLL-import TF-IDF.

**C. API Imports**

Imported Windows API functions are represented using TF-IDF encoding.

- Vocabulary size: 2,715.
- Representation: API-import TF-IDF.

### 3. Feature Engineering

Individual representations are evaluated independently and in combination.

| Representation | Components | Dimensions |
|---|---|---:|
| PE | PE metadata and architecture | 22 |
| DLL | DLL-import TF-IDF | 78 |
| API | API-import TF-IDF | 2,715 |
| PE + DLL | PE and DLL imports | 100 |
| PE + API | PE and API imports | 2,737 |
| PE + DLL + API | All three representations | 2,815 |

The combined representations are constructed through feature concatenation. Sparse representations use SciPy CSR matrices and horizontal stacking.

TF-IDF vectorizers are fitted exclusively on the training partition and subsequently applied to validation and test data to prevent information leakage.

### 4. Dataset Partitioning

The dataset is divided using stratified partitioning with a fixed random seed of 42.

| Partition | Samples |
|---|---:|
| Training | 1,132 |
| Validation | 243 |
| Held-out Test | 243 |
| **Total** | **1,618** |

The partitions serve distinct purposes:

- **Training:** Model fitting.
- **Validation:** Configuration assessment and model selection.
- **Testing:** Final evaluation of configurations with completed test artifacts.

The held-out test partition is not used for model selection.

### 5. Machine-Learning Models

The current experimental framework includes four classification models.

| Model | Category |
|---|---|
| Random Forest (RF) | Classical Machine Learning |
| Support Vector Machine (SVM) | Classical Machine Learning |
| XGBoost | Gradient-Boosted Decision Trees |
| Multilayer Perceptron (MLP) | Neural Network |

The models are evaluated against the available static feature representations to investigate the relationship between feature composition and classification performance.

### 6. Dynamic Analysis — Ongoing

Dynamic analysis is a planned extension of the research workflow.

The objective is to collect behavioral observations from controlled malware execution environments and investigate their usefulness for family classification.

The broader planned direction includes:

- Process and execution activity.
- Windows API and system-event observations.
- Registry operations.
- File-system activity.
- Behavioral sequence extraction.
- Temporal feature representation.

A CNN-LSTM architecture is planned for investigating local behavioral patterns and temporal dependencies in sequential observations.

**Important:** Dynamic behavioral classification has not yet been included in the reported static classification results.

## Experimental Results

The current static classification experiments demonstrate that performance varies according to both feature representation and model configuration.

### Classical Machine-Learning Results

The strongest recorded classical-model validation configuration was Random Forest using combined PE and DLL-import features.

| Metric | Validation Result |
|---|---:|
| Accuracy | 83.13% |
| Macro-F1 | 81.36% |

### MLP Results

The strongest recorded MLP validation configuration was Variant D using PE and DLL-import features.

| Metric | Validation Result |
|---|---:|
| Accuracy | 75.31% |
| Macro-F1 | 73.30% |

### Verified Held-Out Test Results

Only two configurations currently have verified final-test artifacts.

| Model | Representation | Accuracy | Macro-F1 |
|---|---|---:|---:|
| Random Forest | PE | 83.13% | 82.15% |
| MLP Variant D | PE + DLL | 72.43% | 70.90% |

These results should not be interpreted as a controlled comparison of the two model architectures because both the classifier and feature representation differ.

The reported findings are specific to the constructed corpus, its source-derived labels, and the evaluated configurations.

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Research implementation and automation |
| Ubuntu Linux | Static analysis and model experimentation |
| Windows | Malware execution and behavioral observation environment |
| PEfile | Portable Executable parsing |
| NumPy | Numerical computation |
| Pandas | Dataset and feature management |
| Scikit-learn | Classical ML, preprocessing, and evaluation |
| XGBoost | Gradient-boosted classification |
| PyTorch | Neural-network implementation |
| SciPy | Sparse matrix operations |
| Sysmon | Windows system-event monitoring |
| VirtualBox | Isolated virtual-machine infrastructure |
| Kali Linux | Security research environment |
| REMnux | Malware analysis environment |

## Repository Structure

The repository is organized around the research pipeline. The structure below is a proposed documentation layout; individual paths should be updated to match the actual repository.

```text
Adaptive-Honeypot/
│
├── acquisition/
│   ├── acquire_samples.py
│   ├── build_manifest.py
│   └── corpus_manifest.py
│
├── analysis/
│   ├── static/
│   │   ├── extract_pe_features.py
│   │   └── ...
│   │
│   └── dynamic/
│       └── ...
│
├── feature_engineering/
│   ├── ...
│
├── models/
│   ├── random_forest/
│   ├── svm/
│   ├── xgboost/
│   └── mlp/
│
├── evaluation/
│   ├── ...
│
├── documentation/
│   ├── SCHEMA.md
│   └── ...
│
├── requirements.txt
├── README.md
└── .gitignore
```

## Installation and Environment Setup

### Prerequisites

- Python 3.x.
- Ubuntu or another compatible Linux environment for static analysis.
- Git.
- A virtual environment.
- Required Python dependencies.

### Clone the Repository

```bash
git clone https://github.com/<YOUR-USERNAME>/Adaptive-Honeypot.git
cd Adaptive-Honeypot
```

### Create a Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### Install Dependencies

If the repository includes a `requirements.txt` file:

```bash
pip install -r requirements.txt
```

The exact dependency versions and execution commands will be documented as the implementation stabilizes.

## Reproducibility and Experimental Considerations

The research follows several practices intended to support reproducibility:

- SHA-256-based sample identity and integrity verification.
- Fixed dataset partitioning with random seed 42.
- Consistent dataset partitions across evaluated representations.
- Training-only fitting of TF-IDF vectorizers.
- Separate validation and held-out testing stages.
- Recorded model configurations and evaluation metrics.
- Explicit reporting of configurations with verified final-test artifacts.

The project does not claim that the reported results establish universal malware-family classification performance.

## Security and Responsible Research

This repository is intended for cybersecurity research, malware analysis, and defensive security experimentation.

**Malware samples are not included in this repository.**

Malware execution must only take place in appropriately isolated and controlled environments.

Recommended precautions:

- Use dedicated virtual machines.
- Disable shared folders and unnecessary host integration.
- Avoid bridged networking during malware execution.
- Use controlled network simulation where appropriate.
- Maintain VM snapshots and clean recovery states.
- Never execute unknown samples on production or personal systems.

Researchers are responsible for complying with applicable laws, institutional policies, and malware-handling requirements.

## Current Development Status

This project is actively being developed. The following table distinguishes completed research stages from ongoing work.

| Component | Status |
|---|---|
| Malware acquisition workflow | Complete |
| Corpus validation and reconciliation | Complete |
| Malware-family taxonomy | Complete |
| Static PE feature extraction | Complete |
| DLL/API import extraction | Complete |
| Static feature engineering | Complete |
| Dataset partitioning | Complete |
| Classical ML evaluation | Complete |
| Static MLP evaluation | Complete |
| Verified final-test evaluation | Partially complete |
| Dynamic analysis automation | In progress |
| Dynamic behavioral feature engineering | Planned |
| CNN-LSTM classification | Planned |
| Comparative static/dynamic evaluation | Planned |
| Further ablation and error analysis | Planned |

## Roadmap

The planned development direction includes:

- [x] Malware corpus acquisition and validation.
- [x] Static PE feature extraction.
- [x] DLL and API import representation.
- [x] Static feature engineering.
- [x] Classical machine-learning baselines.
- [x] Static MLP experiments.
- [ ] Complete final-test evaluation across selected configurations.
- [ ] Expand dynamic malware behavior collection.
- [ ] Develop behavioral sequence representations.
- [ ] Implement CNN-LSTM classification.
- [ ] Perform comparative static and dynamic evaluation.
- [ ] Conduct additional ablation and error analysis.
- [ ] Integrate the research components into the broader Adaptive-Honeypot framework.

## Research Publication

**Research Title:** Windows Malware Family Classification: An Empirical Evaluation of Static Feature Representations and Classification Models.

Publication details and the final paper will be added when available.

## Contributing

This repository is under active research and development.

Contributions involving reproducibility, malware analysis methodology, feature engineering, model evaluation, and defensive security research are welcome.

Before submitting changes:

1. Clearly document the proposed change.
2. Preserve existing experimental records.
3. Avoid introducing data leakage into evaluation pipelines.
4. Document dependencies and execution requirements.
5. Do not upload malware binaries, credentials, or sensitive research artifacts.

## License

A license will be added once the repository's distribution and contribution requirements have been finalized.

Until then, no permission to reuse, modify, or redistribute the code should be assumed.

## Acknowledgements

This work is conducted as part of cybersecurity research at Sharda University.

The project uses publicly available malware intelligence metadata and open-source security and machine-learning tools.

---

<p align="center">
  <strong>Detection identifies the threat. Classification investigates its family.</strong>
</p>

<p align="center">
  <sub>Adaptive-Honeypot · Windows Malware Research · Active Development</sub>
</p>
