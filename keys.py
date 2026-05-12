import os
try:
    import gmpy2  # noqa: F401 - optional GMP speedup for python-phe
except ImportError:
    pass
from phe import paillier
_PAILLIER_BITS = int(os.environ.get('SPK_PAILLIER_BITS', '512'))
public_key, private_key = paillier.generate_paillier_keypair(n_length=_PAILLIER_BITS)

def get_private_key():
    return private_key

def get_public_key():
    return public_key
