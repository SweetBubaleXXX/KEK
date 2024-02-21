from typing import Literal

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

KEK_ALGORITHM_VERSION = Literal[1]

KEY_SIZE = Literal[2048, 3072, 4096]

SUPPORTED_KEY_SIZES: frozenset[KEY_SIZE] = frozenset((2048, 3072, 4096))

RSA_PUBLIC_EXPONENT = 65537

KEY_ID_HASH_ALGORITHM = hashes.SHA256()

KEY_ID_LENGTH = 8

KEY_SERIALIZATION_ENCODING = serialization.Encoding.PEM

PRIVATE_KEY_FORMAT = serialization.PrivateFormat.PKCS8

PUBLIC_KEY_FORMAT = serialization.PublicFormat.SubjectPublicKeyInfo

SIGNATURE_PADDING = padding.PSS(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH,
)
SIGNATURE_HASH_ALGORITHM = hashes.SHA256()

CHUNK_SIZE = 1024 * 1024
