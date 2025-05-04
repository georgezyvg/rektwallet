from rektWallet.vulnerable_btc_wallet import *
from ecdsa.util import sigdecode_string



wallet = VulnerableBitcoinWallet()

# for i in range(20):
#     k = wallet.nonce_gen.get_nonce()
#     r = (SECP256k1.generator * k).x() % SECP256k1.order
#     print(f"k[{i}] = {k}, r = {r}")



seen_r = set()

for i in range(5_000_000):
    msg = "Test message"
    sig, digest = wallet.sign_transaction(msg)
    r, s = sigdecode_string(bytes.fromhex(sig), SECP256k1.order)
    if r in seen_r:
        print(f"[!!!] Duplicate r found at index {i}: {r}")
        break
    seen_r.add(r)

print(f"Total unique r values: {len(seen_r)}")

