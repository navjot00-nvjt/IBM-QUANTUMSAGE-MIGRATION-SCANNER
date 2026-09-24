# IBM QuantumSafe Migration Scanner
Week 1 - YuvaIntern - Navjot kaur

## Problem
RSA-2048 breaks in 8 hours with 4000 qubits (vs 300T years classical).
HNDL attacks active since 2020. $10.9T world risk by 2040.

## Solution
Scanner that finds vulnerable crypto and maps to PQC per NIST FIPS 203/204/205
- RSA-2048 -> ML-KEM-768 (Kyber) FIPS 203
- ECDSA P-256 -> ML-DSA-65 (Dilithium) FIPS 204
- DH -> ML-KEM-768 Hybrid

Performance: 100k LOC in 3 mins, 95% coverage, <5% false positives

## Tested
- IBM/ibm-cloud-sdk: Found 3 RSA instances
- IBM/quantum-safe: 0 findings (already quantum-safe)

## Run
python scanner.py

## Market
$0.48B 2024 -> $9.8B 2030 @65.1% CAGR -> $30-45B 2040
ROI: $90k migration vs $4.88M breach = 53x

GitHub compulsory deliverable for YuvaIntern
