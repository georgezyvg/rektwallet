from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import hashlib
import binascii
from collections import Counter
from ecdsa.util import sigdecode_string
from ecdsa.curves import SECP256k1



# seen_r = set()
seen_r = {}
signature_data = []

# Define the path to your file
file_path = 'dataSet.txt'  # Update this path if needed

# Read the file
with open(file_path, 'r') as f:
    lines = [line.strip() for line in f.readlines()]

# Extract the public key from the first line
public_key_hex = lines[0].split(":", 1)[1].strip()

# Prepare to store parsed entries
signature_data = []

# Process lines starting after the second line

for line in lines[2:]:
    if ',' not in line:
        continue

    sig_hex, digest_hex = line.split(',', 1)
    try:
        sig_bytes = bytes.fromhex(sig_hex)
        if len(sig_bytes) != 64:
            continue

        r, s = sigdecode_string(sig_bytes, SECP256k1.order)
        z = int(digest_hex, 16)

        if r in seen_r:
            prev = seen_r[r]
            print(f"[!] Duplicate r found: {r}")
            print(f"r1 = {prev['r']}, r2 = {r}")
            print(f"s1 = {prev['s']}, s2 = {s}")
            print(f"z1 = {prev['z']}, z2 = {z}")
            print(f"sig1 = {prev['sig']}")
            print(f"sig2 = {sig_hex}")
            break

        seen_r[r] = {
            'r': r,
            's': s,
            'z': z,
            'sig': sig_hex,
            'digest': digest_hex
        }

        signature_data.append({
            'signature': sig_hex,
            'digest': digest_hex,
            'r': r,
            's': s,
            'z': z
        })

    except ValueError as e:
        print(f"Error parsing line: {line}")
        print(e)
# Check for duplicate r values
r_values = [entry['r'] for entry in signature_data]
r_counts = Counter(r_values)

print("Duplicate r values:")
for r, count in r_counts.items():
    if count > 1:
        print(f"r: {r} — occurs {count} times")

# Optional: print all parsed data
# for entry in signature_data:
#     print(entry)


# print(f"Total unique r values: {len(seen_r)}")
