from rektWallet.vulnerable_btc_wallet import *


wallet = VulnerableBitcoinWallet()


number_of_sigs = 5

wallet = VulnerableBitcoinWallet()
print("Public Key:", wallet.get_public_key())
print("Signature,hash")

for i in range(number_of_sigs):
    msg = f"Send 1 BTC to address_{i} from {wallet.utxo_address}"
    sig, digest = wallet.sign_transaction(msg)
    print(f"{sig},{digest}")
