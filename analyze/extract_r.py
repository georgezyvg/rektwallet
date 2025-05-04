from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

# Generate key
private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())

# Sample message
message = b"sample transaction"

# Sign message
signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))

# Decode signature to get r and s
r, s = decode_dss_signature(signature)

print("r:", r)
