from ecdsa.util import sigdecode_der
from ecdsa.curves import SECP256k1

def extract_r(signature_der: bytes):
    # Dummy values for s and order just to extract r
    r, s = sigdecode_der(signature_der, None)
    return r
