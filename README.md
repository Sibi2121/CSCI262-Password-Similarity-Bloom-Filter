# Password Similarity Detection using Bloom Filters

University of Wollongong in Dubai (UOWD)  
CSCI262 System Security - Group 15  

Group members: Ahan Sunil, Hriday Pradeep, Sibi Varghese, Amberlily El moumni berdai, Huangfu Pinxi

## About the Project

When organizations require frequent password changes, users often take shortcuts. Instead of coming up with a completely fresh password, people usually make minor tweaks to an existing one (for example, changing `password12` to `password13`, capitalizing one letter, or adding a digit at the end).

Standard password storage relies on cryptographic hash functions like SHA-256. Because of the avalanche effect, changing even a single character produces an entirely different hash. This makes regular hash comparisons useless for spotting near-duplicate passwords. On the other hand, checking raw strings against massive breach databases using string distance algorithms (like Levenshtein distance) is slow and requires storing plaintext passwords.

This project implements a proactive password checker that detects structural similarity at registration time without comparing plaintext strings. It converts passwords into Bloom filters using bigrams and double-hashing (SHA-256 and MD5), then evaluates similarity against compromised passwords from the RockYou breach using three metrics:
1. Jaccard similarity
2. Dice similarity
3. Cosine similarity

If any of the three similarity scores meets or exceeds the threshold of 0.6, the candidate password is rejected.

## How It Works

### 1. Bigram Extraction with Padding
Each password is first padded with a leading and trailing space (e.g. ` test `). This ensures that character positions at the start and end of the password are properly captured. The string is then split into overlapping 2-character slices (bigrams).

### 2. Bloom Filter and Double Hashing
The Bloom filter is a 1000-bit array initialized to all zeros. To set the bits for each bigram without calling 20 separate hash functions, we use Kirsch and Mitzenmacher's double-hashing technique:

h_i = (f + i * g) % 1000, for i = 0 to 19

where:
- f is SHA-256(bigram) modulo 1000
- g is MD5(bigram) modulo 1000

The corresponding bits are set to 1 in the filter.

### 3. Similarity Metrics
Given the Bloom filter bit-vectors of a dataset password (B1) and the candidate password (B2):
- gamma: number of positions where both filters have a 1 (intersection)
- k1: total number of 1-bits in B1
- k2: total number of 1-bits in B2

The three coefficients are calculated as:

- Jaccard = gamma / (k1 + k2 - gamma)
- Dice = (2 * gamma) / (k1 + k2)
- Cosine = gamma / (sqrt(k1) * sqrt(k2))

### 4. Decision Rule and Threshold
The default rejection threshold is 0.6.
- If any score (Jaccard, Dice, or Cosine) is >= 0.6, the password is REJECTED.
- If all three scores stay strictly below 0.6, the password is ACCEPTED.

We tested thresholds of 0.5, 0.6, 0.7, and 0.8 during development. A threshold of 0.5 was overly strict and rejected too many valid passwords, while 0.7 and 0.8 allowed minor mutations of compromised passwords to pass through. 0.6 gave the best practical balance.

## Repository Contents

- `main.py`: Standalone Python script with an interactive prompt, single password checking, and a test suite.
- `main.ipynb`: Jupyter notebook version of the implementation.
- `rockyou_subset_15.txt`: Dataset containing 250 compromised passwords from the RockYou breach.
- `CSCI-262_Project_Report.docx`: Full academic project report.
- `requirements.txt`: Environment dependencies for running the Jupyter notebook.
- `LICENSE`: MIT license.

## Setup and Requirements

The script `main.py` uses only Python's standard library (`hashlib`, `math`, `argparse`, `sys`), so no extra packages are needed to run it.

Requirements:
- Python 3.8 or higher

Optional (only if you want to run the Jupyter notebook):
```bash
pip install -r requirements.txt
```

## How to Run

### Run the CLI Script

Interactive mode (prompts for a password between 8 and 10 characters):
```bash
python main.py
```

Check a single password directly:
```bash
python main.py -p password14
```

Run the built-in test suite:
```bash
python main.py --test
```

Custom dataset or threshold:
```bash
python main.py -p mypass123 -d rockyou_subset_15.txt -t 0.65
```

### Run the Jupyter Notebook

Open `main.ipynb` in VS Code or run:
```bash
jupyter notebook main.ipynb
```

## Sample Output

When testing a candidate like `password14` (which closely matches `password13` from the dataset):

```
[*] Loaded 250 compromised passwords from 'rockyou_subset_15.txt'.
[*] Precomputing Bloom filters...
[*] Successfully precomputed 250 Bloom filters.

=====================================================================================
                                 JUSTIF TABLE
=====================================================================================
Original data set    | Jaccard coefficient    | The Dice           | The Cosine
password P           | between beta(P)&beta(UserP) | coefficient        | Similarity
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

When testing a strong, high-entropy password like `X9#qL2!vR`:

```
=====================================================================================
                                 JUSTIF TABLE
=====================================================================================
Original data set    | Jaccard coefficient    | The Dice           | The Cosine
password P           | between beta(P)&beta(UserP) | coefficient        | Similarity
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

## Test Results Summary

| Candidate | Description | Matched Entry | Max Score | Decision |
| :--- | :--- | :--- | :--- | :--- |
| password14 | 1-character suffix mutation of password13 | password13 | 0.8614 | REJECTED |
| 19841985 | Sequential number change from 19841984 | 19841984 | 0.8198 | REJECTED |
| shadow124 | Trailing number increment of shadow123 | shadow123 | 0.8523 | REJECTED |
| lalaland9 | Appended digit mutation of lalaland | lalaland | 0.8010 | REJECTED |
| soulmates1 | Suffix append mutation of soulmates | soulmates | 0.8785 | REJECTED |
| brandon8 | Incremented digit mutation of brandon7 | brandon7 | 0.7977 | REJECTED |
| X9#qL2!vR | Complex alphanumeric and symbols | terminal | 0.2559 | ACCEPTED |
| k9!mZ#4wT | Random alphanumeric string | kulangot | 0.2623 | ACCEPTED |

## Team Contributions

- Ahan Sunil (8398112): Jaccard similarity implementation, report compilation and formatting, documentation on bigrams, Bloom filter construction, and similarity metrics.
- Sibi Varghese (8935166): Bloom filter implementation, JUSTIF table generation, introduction, and conceptual background for SHA-256 and MD5.
- Huangfu Pinxi (8409043): Dice and Cosine similarity functions, implementation section write-up, and algorithm justification.
- Hriday Pradeep (8890766): Application structure, dataset loading, precomputing filter vectors, candidate comparison loop, and decision logic write-up.
- Amberlily El moumni berdai (8983835): Threshold testing across test cases (0.5 to 0.8), test tables, threshold justification, and critical analysis.

## References

1. Berardi, D., Callegati, F., Melis, A., and Prandini, M. (2021). Password similarity using probabilistic data structures. IEEE Access.
2. Kirsch, A., and Mitzenmacher, M. (2006). Less hashing, same performance: building a better Bloom filter. European Symposium on Algorithms (ESA).
3. Blustein, J., and El-Maazawi, A. (2002). Bloom Filters: A tutorial, analysis, and survey. Dalhousie University CS Technical Report.
4. Antognini, C., and Trivadis, A. (2008). Bloom filters. Trivadis Technical Paper.
5. Khelalfa, H. (2026). CSCI262 System Security course materials, University of Wollongong in Dubai.

## License

This project is licensed under the MIT License. See the LICENSE file for details.
