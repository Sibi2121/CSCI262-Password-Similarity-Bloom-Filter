"""
CSCI262 System Security - Password Similarity Detection System
Group 15 - University of Wollongong in Dubai (UOWD)

A proactive password security mechanism utilizing Bloom filters, SHA-256 and MD5
double-hashing, and three similarity metrics (Jaccard, Dice, and Cosine) to detect
and prevent credential mutations derived from compromised password datasets.
"""

import argparse
import hashlib
import math
import sys
from typing import List, Tuple, Optional


# =====================================================================
# BLOOM FILTER CONSTRUCTION
# =====================================================================

def compute_bloom_filter(password: str, filter_size: int = 1000, num_hashes: int = 20) -> List[int]:
    """
    Converts a plaintext password into a fixed-size Bloom filter bit vector.

    Steps:
    1. Pad the password with leading and trailing spaces to capture boundary bigrams.
    2. Extract 2-character sliding window bigrams.
    3. For each bigram, compute SHA-256 and MD5 hashes modulo filter_size.
    4. Generate k hash indices using the double-hashing technique:
       h_i = (f + i * g) % filter_size
    5. Set the corresponding bits in the Bloom filter to 1.

    Args:
        password: The input password string.
        filter_size: Number of bits in the Bloom filter (default 1000).
        num_hashes: Number of hash functions generated per bigram (default 20).

    Returns:
        A list of integers (0 or 1) representing the 1000-bit Bloom filter.
    """
    bloom_filter = [0] * filter_size
    padded_pwd = f" {password} "
    bigrams = [padded_pwd[i:i + 2] for i in range(len(padded_pwd) - 1)]

    for bg in bigrams:
        encoded_bg = bg.encode("utf-8")
        f = int(hashlib.sha256(encoded_bg).hexdigest(), 16) % filter_size
        g = int(hashlib.md5(encoded_bg).hexdigest(), 16) % filter_size

        for i in range(num_hashes):
            h_i = (f + i * g) % filter_size
            bloom_filter[h_i] = 1

    return bloom_filter


# =====================================================================
# SIMILARITY COEFFICIENT METRICS
# =====================================================================

def jaccard(b1: List[int], b2: List[int]) -> float:
    """
    Calculates the Jaccard similarity coefficient between two Bloom filters.

    Formula:
        J(B1, B2) = |B1 ∩ B2| / |B1 ∪ B2| = gamma / (k1 + k2 - gamma)

    where:
        gamma = number of common 1-bits (intersection)
        k1    = number of 1-bits in B1
        k2    = number of 1-bits in B2
    """
    gamma = sum(1 for i in range(len(b1)) if b1[i] == 1 and b2[i] == 1)
    k1 = sum(b1)
    k2 = sum(b2)
    denom = k1 + k2 - gamma
    return gamma / denom if denom != 0 else 0.0


def dice(b1: List[int], b2: List[int]) -> float:
    """
    Calculates the Sørensen-Dice similarity coefficient between two Bloom filters.

    Formula:
        D(B1, B2) = (2 * |B1 ∩ B2|) / (|B1| + |B2|) = (2 * gamma) / (k1 + k2)
    """
    gamma = sum(a and b for a, b in zip(b1, b2))
    k1 = sum(b1)
    k2 = sum(b2)
    return (2 * gamma) / (k1 + k2) if (k1 + k2) != 0 else 0.0


def cosine(b1: List[int], b2: List[int]) -> float:
    """
    Calculates the Cosine similarity between two Bloom filters.

    Formula:
        C(B1, B2) = (B1 · B2) / (||B1|| * ||B2||) = gamma / (sqrt(k1) * sqrt(k2))
    """
    gamma = sum(a and b for a, b in zip(b1, b2))
    k1 = sum(b1)
    k2 = sum(b2)
    denom = math.sqrt(k1) * math.sqrt(k2)
    return gamma / denom if denom != 0 else 0.0


# =====================================================================
# DATASET LOADING AND PRECOMPUTATION
# =====================================================================

def load_password_dataset(filename: str) -> List[str]:
    """
    Loads passwords from a text file, filtering out blank lines.
    """
    with open(filename, "r", encoding="utf-8", errors="ignore") as file:
        passwords = [line.strip() for line in file if line.strip()]
    return passwords


def precompute_dataset_filters(passwords: List[str]) -> List[Tuple[str, List[int]]]:
    """
    Precomputes the Bloom filter representation for each password in the dataset.

    Returns:
        A list of tuples: (password_string, bloom_filter_vector)
    """
    return [(pwd, compute_bloom_filter(pwd)) for pwd in passwords]


# =====================================================================
# PASSWORD CHECKER ENGINE
# =====================================================================

def password_checker(
    candidate: str,
    dataset_filters: List[Tuple[str, List[int]]],
    threshold: float = 0.6,
) -> Tuple[str, Optional[str], float, float, float]:
    """
    Evaluates a candidate password against precomputed dataset Bloom filters.

    If any of the three similarity scores (Jaccard, Dice, Cosine) meets or exceeds
    the threshold, the candidate is immediately REJECTED.
    Otherwise, after evaluating all dataset entries, it is ACCEPTED with details of
    the highest similarity observed across the dataset.

    Returns:
        (decision, matched_password, best_j_score, best_d_score, best_c_score)
    """
    candidate_filter = compute_bloom_filter(candidate)

    best_password: Optional[str] = None
    best_j_score = 0.0
    best_d_score = 0.0
    best_c_score = 0.0
    highest_score = 0.0

    for dataset_password, dataset_filter in dataset_filters:
        j_score = jaccard(candidate_filter, dataset_filter)
        d_score = dice(candidate_filter, dataset_filter)
        c_score = cosine(candidate_filter, dataset_filter)

        current_highest = max(j_score, d_score, c_score)

        if current_highest > highest_score:
            highest_score = current_highest
            best_password = dataset_password
            best_j_score = j_score
            best_d_score = d_score
            best_c_score = c_score

        # Early exit on threshold violation
        if j_score >= threshold or d_score >= threshold or c_score >= threshold:
            return ("REJECTED", dataset_password, j_score, d_score, c_score)

    return ("ACCEPTED", best_password, best_j_score, best_d_score, best_c_score)


# =====================================================================
# REPORT FORMATTING AND DISPLAY
# =====================================================================

def display_justif_table(
    candidate: str,
    result: str,
    matched_password: Optional[str],
    j_score: float,
    d_score: float,
    c_score: float,
    threshold: float,
) -> None:
    """
    Prints the JUSTIF table and formal security justification proof.
    """
    # Ensure console output handles unicode or gracefully falls back
    beta_label = "β(P)&β(UserP)"
    try:
        if sys.stdout.encoding and "utf" not in sys.stdout.encoding.lower():
            beta_label = "beta(P)&beta(UserP)"
    except Exception:
        beta_label = "beta(P)&beta(UserP)"

    print("\n" + "=" * 85)
    print("                                 JUSTIF TABLE")
    print("=" * 85)
    print(f"{'Original data set':<20} | {'Jaccard coefficient':<22} | {'The Dice':<18} | {'The Cosine'}")
    print(f"{'password P':<20} | {f'between {beta_label}':<22} | {'coefficient':<18} | {'Similarity'}")
    print("-" * 85)
    print(f"{str(matched_password):<20} | {round(j_score, 4):<22} | {round(d_score, 4):<18} | {round(c_score, 4)}")
    print("=" * 85)

    print("\nJUSTIFICATION (PROOF)")
    print(f"Candidate Password : '{candidate}'")
    print(f"Final Decision     : {result}")
    print(f"Enforced Threshold : {threshold}")

    if result == "REJECTED":
        print(f"Proof: The candidate password (UserP) is structurally too similar to '{matched_password}'.")
        print(f"Based on the JUSTIF table above, the system enforces a strict threshold of {threshold}.")

        reasons = []
        if j_score >= threshold:
            reasons.append(f"Jaccard ({round(j_score, 4)})")
        if d_score >= threshold:
            reasons.append(f"Dice ({round(d_score, 4)})")
        if c_score >= threshold:
            reasons.append(f"Cosine ({round(c_score, 4)})")

        print("The password was rejected because the following metrics met or exceeded that threshold:")
        for r in reasons:
            print(f"  - {r} >= {threshold}")
    else:
        print("Proof: The candidate password (UserP) is structurally distinct from all compromised passwords.")
        print(f"Based on the JUSTIF table above, the closest matching password was '{matched_password}'.")
        print(f"However, all calculated similarity metrics remained strictly below the {threshold} threshold.")
        print("Therefore, the password is safe to be ACCEPTED.")


# =====================================================================
# DEMO TEST SUITE
# =====================================================================

def run_test_suite(dataset_filters: List[Tuple[str, List[int]]], threshold: float = 0.6) -> None:
    """
    Executes a standard evaluation suite across representative test passwords.
    """
    test_cases = [
        ("password14", "Minor mutation of 'password13' (compromised)"),
        ("19841985",   "Consecutive mutation of '19841984' (compromised)"),
        ("shadow124",  "Minor mutation of 'shadow123' (compromised)"),
        ("lalaland9",  "Appended digit mutation of 'lalaland' (compromised)"),
        ("X9#qL2!vR",  "Random high-entropy password (should be ACCEPTED)"),
        ("k9!mZ#4wT",  "Random alphanumeric password (should be ACCEPTED)"),
        ("soulmates1", "Suffix mutation of 'soulmates' (compromised)"),
        ("brandon8",   "Suffix mutation of 'brandon7' (compromised)"),
    ]

    print("\n" + "=" * 90)
    print("                             EMPIRICAL EVALUATION SUITE")
    print("=" * 90)
    print(f"{'Candidate':<14} | {'Expected / Description':<36} | {'Result':<10} | {'Match':<12} | {'Max Score'}")
    print("-" * 90)

    for pwd, desc in test_cases:
        res, match, j, d, c = password_checker(pwd, dataset_filters, threshold)
        max_s = max(j, d, c)
        print(f"{pwd:<14} | {desc:<36} | {res:<10} | {str(match):<12} | {round(max_s, 4)}")

    print("=" * 90 + "\n")


# =====================================================================
# CLI ENTRY POINT
# =====================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="CSCI262 Bloom Filter Password Similarity Detection System"
    )
    parser.add_argument(
        "-d", "--dataset",
        default="rockyou_subset_15.txt",
        help="Path to compromised passwords file (default: rockyou_subset_15.txt)"
    )
    parser.add_argument(
        "-t", "--threshold",
        type=float,
        default=0.6,
        help="Similarity rejection threshold (default: 0.6)"
    )
    parser.add_argument(
        "-p", "--password",
        type=str,
        default=None,
        help="Candidate password to evaluate"
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Run the pre-configured test suite"
    )

    args = parser.parse_args()

    # Load dataset
    try:
        passwords = load_password_dataset(args.dataset)
    except FileNotFoundError:
        print(f"Error: Dataset file '{args.dataset}' not found.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Loaded {len(passwords)} compromised passwords from '{args.dataset}'.")
    print("[*] Precomputing Bloom filters...")
    dataset_filters = precompute_dataset_filters(passwords)
    print(f"[*] Successfully precomputed {len(dataset_filters)} Bloom filters.")

    if args.test:
        run_test_suite(dataset_filters, args.threshold)
        return

    # Determine candidate password
    candidate = args.password
    if candidate is None:
        candidate = input("\nEnter a candidate password (8-10 characters): ").strip()

    while len(candidate) < 8 or len(candidate) > 10:
        print("Invalid password length. Password must be between 8 and 10 characters.")
        candidate = input("Please enter another password: ").strip()

    result, matched_password, j_score, d_score, c_score = password_checker(
        candidate,
        dataset_filters,
        args.threshold,
    )

    display_justif_table(
        candidate,
        result,
        matched_password,
        j_score,
        d_score,
        c_score,
        args.threshold,
    )


if __name__ == "__main__":
    main()
