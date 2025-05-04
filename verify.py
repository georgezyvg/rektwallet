from ecdsa import SigningKey, SECP256k1

private_key = input("private key: ")
private_key = int(private_key)
sk = SigningKey.from_secret_exponent(private_key, curve=SECP256k1)
vk = sk.verifying_key

print("Recovered public key:", vk.to_string().hex())
