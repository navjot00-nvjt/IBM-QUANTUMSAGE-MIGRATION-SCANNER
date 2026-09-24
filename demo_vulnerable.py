# Demo vulnerable code for scanner test - BEFORE PQC
import rsa
# RSA-2048 - Vulnerable to Shor's algorithm, breaks in 8 hours with 4000 qubits
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# ECDSA P-256 - Vulnerable
import ecdsa
sk = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)  # P-256

# TLS 1.2 RSA - Non compliant with CNSA 2.0
# cipher = TLS_RSA_WITH_AES_128_GCM_SHA256
