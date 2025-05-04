
# vulnerable_bitcoinWallet.py

import hashlib
from ecdsa import SigningKey, SECP256k1


class WeakNonceGenerator:
    def __init__(self):
        self.seed = 42  # Fixed seed on wallet startup
        self.a = 1103515245
        self.c = 12345
        self.m = 2**20  # Small modulus leads to short cycle about 1M values
        # self.m = 2**12 # only 4096 possible values 
        self.state = self.seed
        self.order = SECP256k1.order

    def get_nonce(self):
        while True:
            self.state = (self.a * self.state + self.c) % self.m
            # Ensure k is in valid ECDSA range
            k = self.state % self.order
            if k != 0:
                return k

def sha256(msg):
    return hashlib.sha256(msg.encode()).digest()

class VulnerableBitcoinWallet:
    def __init__(self):
        self.sk = SigningKey.generate(curve=SECP256k1)
        self.vk = self.sk.verifying_key
        self.nonce_gen = WeakNonceGenerator()
        #generated using the generateAddress.py in the reference folder
        self.utxo_address = "1HUFGAW6Ex3sA5m3Ejg5r9HCp9YSqRmt3p"

    def sign_transaction(self, message):
        k = self.nonce_gen.get_nonce()
        digest = sha256(message)
        signature = self.sk.sign_digest(digest, k=k)
        return signature.hex(), digest.hex()

    def get_public_key(self):
        return self.vk.to_string().hex()

if __name__ == "__main__":
    wallet = VulnerableBitcoinWallet()
    print("Public Key:", wallet.get_public_key())
    
    for i in range(10):
        msg = f"Send 1 BTC to address_{i} from {wallet.utxo_address}"
        sig, digest = wallet.sign_transaction(msg)
        print(f"Transaction {i}:")
        print("  Message:", msg)
        print("  Digest:", digest)
        print("  Signature:", sig)
        print()
