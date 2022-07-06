from __future__ import annotations

from typing import Optional

from cryptography.hazmat.primitives import hashes

from .key_backend import PrivateKey, PublicKey, SymmetricKey
from .key_backend.base import BasePrivateKey, BasePublicKey


class KEK(BasePrivateKey):
    algorithm = "KEK"
    default_size = 4096
    id_length = 16

    def __init__(self, private_key_object: PrivateKey) -> None:
        self._private_key = private_key_object

    @property
    def key_size(self) -> int:
        return self._private_key.key_size

    @property
    def key_id(self) -> str:
        if not hasattr(self, "_key_id"):
            digest = hashes.Hash(hashes.SHA256())
            digest.update(self._private_key.public_key.serialize())
            self._key_id = digest.finalize().hex()[:KEK.id_length]
        return self._key_id

    @property
    def public_key(self) -> PublicKEK:
        return PublicKEK(self._private_key.public_key)

    @staticmethod
    def generate(key_size: Optional[int]) -> KEK:
        if key_size is None:
            key_size = KEK.default_size
        private_key = PrivateKey.generate(key_size)
        return KEK(private_key)

    @staticmethod
    def load(serialized_key: bytes, password: Optional[bytes] = None) -> KEK:
        private_key = PrivateKey.load(serialized_key, password)
        return KEK(private_key)

    def serialize(self, password: Optional[bytes] = None) -> bytes:
        return self._private_key.serialize(password)

    def encrypt(self) -> bytes:
        pass

    def decrypt(self) -> bytes:
        pass

    def sign(self, data: bytes) -> bytes:
        return self._private_key.sign(data)

    def verify(self, signature: bytes, data: bytes) -> bool:
        return self._private_key.verify(signature, data)


class PublicKEK(BasePublicKey):
    algorithm = "KEK"

    def __init__(self, public_key_object: PublicKey) -> None:
        self._public_key = public_key_object

    @property
    def key_id(self) -> str:
        if not hasattr(self, "_key_id"):
            digest = hashes.Hash(hashes.SHA256())
            digest.update(self._public_key.serialize())
            self._key_id = digest.finalize().hex()[:KEK.id_length]
        return self._key_id

    @staticmethod
    def load(serialized_key: bytes) -> PublicKEK:
        public_key = PublicKey.load(serialized_key)
        return PublicKEK(public_key)

    def serialize(self) -> bytes:
        return self._public_key.serialize()

    def encrypt(self) -> bytes:
        pass

    def verify(self, signature: bytes, data: bytes) -> bool:
        return self._public_key.verify(signature, data)
