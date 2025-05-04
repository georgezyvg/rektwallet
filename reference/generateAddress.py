from ecdsa import SigningKey, SECP256k1
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import hashlib
import base58

# 1. Generate ECDSA private key using secp256k1 curve
private_key = SigningKey.generate(curve=SECP256k1)
public_key = private_key.get_verifying_key()

# 2. Get the public key in uncompressed format (prefix with 0x04)
public_key_bytes = b'\x04' + public_key.to_string()

# 3. SHA-256 hash using cryptography
digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
digest.update(public_key_bytes)
sha256_hash = digest.finalize()

# 4. RIPEMD-160 hash using hashlib (not in cryptography)
ripemd160 = hashlib.new('ripemd160')
ripemd160.update(sha256_hash)
ripemd160_hash = ripemd160.digest()

# 5. Add version byte (0x00 for Bitcoin mainnet)
version_byte = b'\x00'
extended_ripemd160 = version_byte + ripemd160_hash

# 6. Compute checksum (SHA-256 twice)
digest1 = hashes.Hash(hashes.SHA256(), backend=default_backend())
digest1.update(extended_ripemd160)
intermediate = digest1.finalize()

digest2 = hashes.Hash(hashes.SHA256(), backend=default_backend())
digest2.update(intermediate)
checksum = digest2.finalize()[:4]

# 7. Append checksum
binary_address = extended_ripemd160 + checksum

# 8. Base58 encode
bitcoin_address = base58.b58encode(binary_address).decode('utf-8')

# Output
print("Private Key (Hex):")
print(private_key.to_string().hex())

print("\nPublic Key (Uncompressed Hex):")
print(public_key_bytes.hex())

print("\nBitcoin Address:")
print(bitcoin_address)
