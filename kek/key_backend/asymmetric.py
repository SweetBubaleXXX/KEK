from __future__ import annotations

from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import (RSAPrivateKey,
                                                           RSAPublicKey)

from .base import BasePrivateKey, BasePublicKey


class PaddingMixin:
    encryption_padding = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
    signing_padding = padding.PSS(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    )
    signing_algorithm = hashes.SHA256()


class PrivateKey(BasePrivateKey, PaddingMixin):
    algorithm = "RSA"
    encoding = serialization.Encoding.PEM
    format = serialization.PrivateFormat.PKCS8

    def __init__(self, private_key_object: RSAPrivateKey) -> None:
        self.private_key = private_key_object

    @property
    def public_key(self) -> PublicKey:
        if not hasattr(self, "_public_key"):
            self.gen_public_key()
        return self._public_key

    @staticmethod
    def generate(key_size: int = 4096) -> PrivateKey:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        return PrivateKey(private_key)

    @staticmethod
    def load(serialized_key: bytes, password: Optional[bytes]) -> PrivateKey:
        private_key = serialization.load_pem_private_key(
            serialized_key,
            password
        )
        return PrivateKey(private_key)

    def serialize(self, password: Optional[bytes]) -> bytes:
        if password:
            encryption_algorithm = serialization.BestAvailableEncryption(
                password)
        else:
            encryption_algorithm = serialization.NoEncryption()
        return self.private_key.private_bytes(
            encoding=PrivateKey.encoding,
            format=PrivateKey.format,
            encryption_algorithm=encryption_algorithm
        )

    def encrypt(self, data: bytes) -> bytes:
        return self.public_key.encrypt(data)

    def decrypt(self, encrypted_data: bytes) -> bytes:
        return self.private_key.decrypt(
            encrypted_data,
            padding=PrivateKey.encryption_padding
        )

    def sign(self, data: bytes) -> bytes:
        return self.private_key.sign(
            data,
            padding=PrivateKey.signing_padding,
            algorithm=PrivateKey.signing_algorithm
        )

    def verify(self, signature: bytes, data: bytes) -> bool:
        return self.public_key.verify(signature, data)

    def gen_public_key(self) -> PublicKey:
        public_key_object = self.private_key.public_key()
        self._public_key = PublicKey(public_key_object)
        return self._public_key


class PublicKey(BasePublicKey, PaddingMixin):
    algorithm = "RSA"
    encoding = serialization.Encoding.PEM
    format = serialization.PublicFormat.SubjectPublicKeyInfo

    def __init__(self, public_key_object: RSAPublicKey) -> None:
        self.public_key = public_key_object

    @staticmethod
    def load(serialized_key: bytes) -> PublicKey:
        public_key = serialization.load_pem_public_key(serialized_key)
        return PublicKey(public_key)

    def serialize(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=PublicKey.encoding,
            format=PublicKey.format
        )

    def encrypt(self, data: bytes) -> bytes:
        return self.public_key.encrypt(
            data,
            padding=PublicKey.encryption_padding
        )

    def verify(self, signature: bytes, data: bytes) -> bool:
        try:
            self.public_key.verify(
                signature,
                data,
                PublicKey.signing_padding,
                PublicKey.signing_algorithm
            )
        except InvalidSignature:
            return False
        else:
            return True
