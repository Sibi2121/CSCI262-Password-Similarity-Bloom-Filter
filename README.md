# Proactive Password Similarity Detection using Bloom Filters & Double Hashing

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Domain: System Security](https://img.shields.io/badge/Domain-System%20Security-red.svg)](#)
[![Institution](https://img.shields.io/badge/UOWD-CSCI262-orange.svg)](https://www.uowdubai.ac.ae/)

> **CSCI262 System Security — Final Project / Group 15**  
> *University of Wollongong in Dubai (UOWD)*  
> Authors: **Ahan Sunil**, **Hriday Pradeep**, **Sibi Varghese**, **Amberlily El moumni berdai**, **Huangfu Pinxi**

---

## 📌 Table of Contents

- [Overview & Motivation](#-overview--motivation)
- [The Problem: The Avalanche Effect & Credential Mutations](#-the-problem-the-avalanche-effect--credential-mutations)
- [Technical Architecture & Methodology](#-technical-architecture--methodology)
  - [1. Bigram Tokenization & Boundary Padding](#1-bigram-tokenization--boundary-padding)
  - [2. Double Hashing with SHA-256 and MD5](#2-double-hashing-with-sha-256-and-md5)
  - [3. Bloom Filter Vector Representation](#3-bloom-filter-vector-representation)
  - [4. Similarity Metrics (Jaccard, Dice, Cosine)](#4-similarity-metrics-jaccard-dice-cosine)
  - [5. Decision Logic & Threshold Calibration](#5-decision-logic--threshold-calibration)
- [Project Structure](#-project-structure)
- [Getting Started](#-getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Usage Guide](#-usage-guide)
  - [Option A: Standalone CLI (`main.py`)](#option-a-standalone-cli-mainpy)
  - [Option B: Interactive Jupyter Notebook (`main.ipynb`)](#option-b-interactive-jupyter-notebook-mainipynb)
- [Sample Execution & Output](#-sample-execution--output)
  - [The JUSTIF Table](#the-justif-table)
  - [Rejection Justification Proof](#rejection-justification-proof)
- [Empirical Evaluation & Test Cases](#-empirical-evaluation--test-cases)
- [Authors & Task Distribution](#-authors--task-distribution)
- [References](#-references)
- [License](#-license)

---

## 📖 Overview & Motivation

Periodic credential change policies in enterprise systems frequently induce usability fatigue. In response, users routinely apply minor, predictable mutations to previously used or common passwords—such as incrementing trailing numbers (`password12` → `password13`), changing case, or replacing characters with leetspeak equivalents. 

Such behavioral patterns leave accounts highly vulnerable to automated credential mutation attacks and dictionary attacks derived from massive publicly breached credential sets (e.g., **RockYou**).

This project implements a **proactive similarity-based detection mechanism** designed to operate at the point of user registration. Rather than relying on exact-match lookups or computationally expensive plaintext string comparisons (such as Levenshtein edit distance), this architecture translates passwords into **probabilistic Bloom filter bit-vectors** and computes structural similarity across three mathematical metrics:
1. **Jaccard Similarity Coefficient**
2. **Sørensen-Dice Coefficient**
3. **Cosine Similarity**

---

## ⚡ The Problem: The Avalanche Effect & Credential Mutations

Standard cryptographic password storage relies on secure one-way hash functions (e.g., SHA-256, bcrypt, Argon2). While essential for authentication, these hash functions feature a strict **avalanche effect**: altering even a single character in the input string changes approximately 50% of the output bits unpredictably:

```
SHA-256("password13") = 398c257ca9...
SHA-256("password14") = 8d42d3be29...  (0% discernible correlation)
```

Consequently, traditional cryptographic hashing **cannot** detect structural proximity. Storing plaintext passwords for Levenshtein comparisons introduces catastrophic privacy risks and $O(N \cdot L_1 \cdot L_2)$ runtime overheads across large breach corpuses.

### The Solution
By breaking strings into overlapping character **bigrams** and projecting them into a **1000-bit Bloom filter vector** via **double hashing**, structural similarities are preserved in bitwise overlap space without preserving the original plaintext.

---

## 🔬 Technical Architecture & Methodology

```
+-------------------------------------------------------------+
|                     Candidate Password                      |
|                      e.g., "password14"                     |
+-------------------------------------------------------------+
                              |
                              v
       +-----------------------------------------------+
       | 1. Boundary Padding & Bigram Tokenization     |
       |    " password14 "                             |
       |    -> [' p', 'pa', 'as', 'ss', ..., '4 ']     |
       +-----------------------------------------------+
                              |
                              v
       +-----------------------------------------------+
       | 2. Cryptographic Double Hashing (k = 20)      |
       |    f = SHA-256(bg) % 1000                     |
       |    g = MD5(bg)     % 1000                     |
       |    h_i = (f + i * g) % 1000, for i in 0..19   |
       +-----------------------------------------------+
                              |
                              v
       +-----------------------------------------------+
       | 3. Bloom Filter Vector Representation (1000b) |
       |    β(candidate) = [0, 1, 0, 0, 1, 1, ...]     |
       +-----------------------------------------------+
                              |
                              v
       +-----------------------------------------------+
       | 4. Vectorized Metric Comparison vs Dataset    |
       |    - Jaccard Similarity                       |
       |    - Sørensen-Dice Coefficient                |
       |    - Cosine Similarity                        |
       +-----------------------------------------------+
                              |
                              v
       +-----------------------------------------------+
       | 5. Decision Engine (Threshold τ = 0.6)        |
       |    IF max(J, D, C) >= 0.6 -> REJECT           |
       |    ELSE                  -> ACCEPT            |
       +-----------------------------------------------+
                              |
                              v
       +-----------------------------------------------+
       | 6. JUSTIF Table & Cryptographic Proof Output  |
       +-----------------------------------------------+
```

### 1. Bigram Tokenization & Boundary Padding
The password string is first bounded with leading and trailing spaces:
```python
padded_pwd = f" {password} "
```
Boundary padding ensures that prefix and suffix character positions are distinguished (e.g., `"pass"` as a prefix vs `"pass"` in the middle of a string). Sliding 2-character windows are extracted:
$$\text{Bigrams}(P) = \{P[i:i+2] \mid 0 \le i < |P| - 1\}$$

### 2. Double Hashing with SHA-256 and MD5
To avoid the computational cost of evaluating 20 distinct cryptographic hash functions, the system employs Kirsch and Mitzenmacher's double-hashing technique:
$$h_i(x) = (f(x) + i \cdot g(x)) \pmod m, \quad i \in \{0, 1, \dots, 19\}$$
where:
- $f(x) = \text{int}(\text{SHA-256}(x)_{16}) \pmod{1000}$
- $g(x) = \text{int}(\text{MD5}(x)_{16}) \pmod{1000}$
- $m = 1000$ (size of the bit-array)
- $k = 20$ (number of hash slices generated per bigram)

### 3. Bloom Filter Vector Representation
A 1000-bit vector $\beta(P) \in \{0, 1\}^{1000}$ is populated by setting:
$$\beta(P)[h_i(bg)] = 1 \quad \forall bg \in \text{Bigrams}(P), \forall i \in \{0, \dots, 19\}$$

### 4. Similarity Metrics (Jaccard, Dice, Cosine)
Let $B_1 = \beta(P_{\text{dataset}})$ and $B_2 = \beta(P_{\text{candidate}})$.  
Define:
- $\gamma = |B_1 \cap B_2| = \sum_{j=0}^{m-1} (B_1[j] \land B_2[j])$ (overlapping 1-bits)
- $k_1 = \sum_{j=0}^{m-1} B_1[j]$ (Hamming weight of $B_1$)
- $k_2 = \sum_{j=0}^{m-1} B_2[j]$ (Hamming weight of $B_2$)

#### Jaccard Similarity
Measures the ratio of the intersection size to the union size:
$$J(B_1, B_2) = \frac{|B_1 \cap B_2|}{|B_1 \cup B_2|} = \frac{\gamma}{k_1 + k_2 - \gamma}$$

#### Sørensen-Dice Coefficient
Gives double weight to shared positive attributes:
$$D(B_1, B_2) = \frac{2 \cdot |B_1 \cap B_2|}{|B_1| + |B_2|} = \frac{2\gamma}{k_1 + k_2}$$

#### Cosine Similarity
Evaluates the geometric angle between the two bit vectors in 1000-dimensional Euclidean space:
$$C(B_1, B_2) = \frac{B_1 \cdot B_2}{\|B_1\| \cdot \|B_2\|} = \frac{\gamma}{\sqrt{k_1} \cdot \sqrt{k_2}}$$

### 5. Decision Logic & Threshold Calibration
The system enforces a policy threshold $\tau = 0.6$:
$$\text{Decision} = \begin{cases} \text{REJECTED}, & \text{if } \max(J, D, C) \ge 0.6 \\ \text{ACCEPTED}, & \text{otherwise} \end{cases}$$

- **Threshold Analysis ($\tau = 0.6$)**:
  - $\tau = 0.5$: Too aggressive; produced false positives rejecting safe, diverse candidate passwords.
  - $\tau = 0.7$ / $0.8$: Too lenient; allowed slight mutations of common compromised passwords to bypass security.
  - $\tau = 0.6$: Optimal empirical balance; strictly caught 1-character suffix/prefix/leetspeak mutations while admitting sufficiently distinct passwords.

---

## 📂 Project Structure

```
.
├── CSCI-262_Project_Report.docx   # Comprehensive academic project report
├── LICENSE                        # MIT Open Source License
├── README.md                      # Complete system documentation (this file)
├── main.ipynb                     # Interactive Jupyter Notebook implementation
├── main.py                        # Standalone Python CLI executable & test runner
├── requirements.txt               # Dependencies for Jupyter / Python environment
└── rockyou_subset_15.txt          # Subset of 250 compromised passwords from RockYou
```

---

## 🚀 Getting Started

### Prerequisites
- Python 3.8 or higher
- Git

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Sibi21/CSCI262-Password-Similarity-Bloom-Filter.git
   cd CSCI262-Password-Similarity-Bloom-Filter
   ```

2. **(Optional) Install dependencies for Jupyter:**
   ```bash
   pip install -r requirements.txt
   ```
   *Note: The CLI script `main.py` uses only Python standard libraries (`hashlib`, `math`, `sys`, `argparse`) and has zero external dependencies.*

---

## 💻 Usage Guide

### Option A: Standalone CLI (`main.py`)

#### 1. Interactive Mode
Prompts you to enter a candidate password (enforcing the 8–10 character policy):
```bash
python main.py
```

#### 2. Direct Password Argument
Evaluate a specific password directly:
```bash
python main.py -p password14
```

#### 3. Run Pre-configured Test Suite
Executes the evaluation matrix comparing mutated passwords and random high-entropy passwords against the dataset:
```bash
python main.py --test
```

#### 4. Custom Dataset & Threshold
```bash
python main.py -p mySecret99 -d rockyou_subset_15.txt -t 0.65
```

---

### Option B: Interactive Jupyter Notebook (`main.ipynb`)

1. Start Jupyter:
   ```bash
   jupyter notebook main.ipynb
   ```
2. Execute the notebook cell to load the dataset, precompute filters, and test candidate passwords interactively.

---

## 📊 Sample Execution & Output

### Example 1: Compromised Mutation (`password14`)
When testing `password14` (a mutation of breached entry `password13`):

```
[*] Loaded 250 compromised passwords from 'rockyou_subset_15.txt'.
[*] Precomputing Bloom filters...
[*] Successfully precomputed 250 Bloom filters.

=====================================================================================
                                 JUSTIF TABLE
=====================================================================================
Original data set    | Jaccard coefficient    | The Dice           | The Cosine
password P           | between β(P)&β(UserP)  | coefficient        | Similarity
-------------------------------------------------------------------------------------
password13           | 0.7556                 | 0.8608             | 0.8614
=====================================================================================

JUSTIFICATION (PROOF)
Candidate Password : 'password14'
Final Decision     : REJECTED
Enforced Threshold : 0.6
Proof: The candidate password (UserP) is structurally too similar to 'password13'.
Based on the JUSTIF table above, the system enforces a strict threshold of 0.6.
The password was rejected because the following metrics met or exceeded that threshold:
  - Jaccard (0.7556) >= 0.6
  - Dice (0.8608) >= 0.6
  - Cosine (0.8614) >= 0.6
```

---

### Example 2: Strong Candidate Password (`X9#qL2!vR`)
When testing a random high-entropy candidate password:

```
=====================================================================================
                                 JUSTIF TABLE
=====================================================================================
Original data set    | Jaccard coefficient    | The Dice           | The Cosine
password P           | between β(P)&β(UserP)  | coefficient        | Similarity
-------------------------------------------------------------------------------------
terminal             | 0.1467                 | 0.2558             | 0.2559
=====================================================================================

JUSTIFICATION (PROOF)
Candidate Password : 'X9#qL2!vR'
Final Decision     : ACCEPTED
Enforced Threshold : 0.6
Proof: The candidate password (UserP) is structurally distinct from all compromised passwords.
Based on the JUSTIF table above, the closest matching password was 'terminal'.
However, all calculated similarity metrics remained strictly below the 0.6 threshold.
Therefore, the password is safe to be ACCEPTED.
```

---

## 🧪 Empirical Evaluation & Test Cases

The detection engine was evaluated across mutation categories against the `rockyou_subset_15.txt` breach dataset:

| Candidate | Mutation Category | Target Compromised Match | Max Similarity Score | Decision ($\tau = 0.6$) |
| :--- | :--- | :--- | :---: | :---: |
| `password14` | 1-Character Suffix Increment | `password13` | **0.8614** | ❌ **REJECTED** |
| `19841985` | Repeated Numeric Pattern Mutation | `19841984` | **0.8198** | ❌ **REJECTED** |
| `shadow124` | Trailing Sequence Mutation | `shadow123` | **0.8523** | ❌ **REJECTED** |
| `lalaland9` | Appended Digit Mutation | `lalaland` | **0.8010** | ❌ **REJECTED** |
| `soulmates1` | Trailing Numeric Append | `soulmates` | **0.8785** | ❌ **REJECTED** |
| `brandon8` | Sequential Number Increment | `brandon7` | **0.7977** | ❌ **REJECTED** |
| `X9#qL2!vR` | High-Entropy Alphanumeric + Symbols | `terminal` | **0.2559** | ✅ **ACCEPTED** |
| `k9!mZ#4wT` | Random Complex Alphanumeric | `kulangot` | **0.2623** | ✅ **ACCEPTED** |

---

## 👥 Authors & Task Distribution

| Name | Student ID | Academic Email | Contributions & Work Distribution |
| :--- | :---: | :--- | :--- |
| **Ahan Sunil** | 8398112 | as8997@uowmail.edu.au | Implemented the Jaccard similarity function; formatted and compiled the full report; documented bigram mechanics, Bloom filter design, and similarity metrics in data structure justification. |
| **Sibi Varghese** | 8935166 | svp967@uowmail.edu.au | Implemented the Bloom filter generator and the JUSTIF reporting table; authored problem introduction and cryptographic hashing (SHA-256 / MD5) conceptual foundations. |
| **Huangfu Pinxi** | 8409043 | ph382@uowmail.edu.au | Implemented the Sørensen-Dice and Cosine similarity functions; authored the Implementation section, module descriptions, and algorithmic justification (bigrams + double hashing). |
| **Hriday Pradeep** | 8890766 | hpk687@uowmail.edu.au | Developed the main application flow (dataset loading, precomputed filters, candidate evaluation across all 3 metrics); co-authored decision logic subsection. |
| **Amberlily El moumni berdai** | 8983835 | aemb887@uowmail.edu.au | Conducted empirical threshold sensitivity evaluations ($\tau \in \{0.5, 0.6, 0.7, 0.8\}$); authored results tables, threshold justifications, and critical analysis/limitations. |

---

## 📚 References

1. **Berardi, D., Callegati, F., Melis, A., & Prandini, M.** (2021). *Password similarity using probabilistic data structures*. IEEE Access.
2. **Kirsch, A., & Mitzenmacher, M.** (2006). *Less hashing, same performance: building a better Bloom filter*. European Symposium on Algorithms (ESA).
3. **Blustein, J., & El-Maazawi, A.** (2002). *Bloom Filters: A tutorial, analysis, and survey*. Dalhousie University CS Technical Report.
4. **Antognini, C., & Trivadis, A.** (2008). *Bloom filters*. Trivadis Technical Paper.
5. **Khelalfa, H.** (2026). *CSCI262 System Security lecture slides and project specifications*, University of Wollongong in Dubai.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE) — see the LICENSE file for details.
