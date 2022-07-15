from __future__ import annotations

from typing import Optional, Type

from cryptography.hazmat.primitives import hashes

from . import exceptions
from .asymmetric import PrivateKey, PublicKey
from .base import BasePrivateKey, BasePublicKey
from .exceptions import raises
from .symmetric import SymmetricKey


class PrivateKEK(BasePrivateKey):
    algorithm = f"{PrivateKey.algorithm}+{SymmetricKey.algorithm}"
    id_length = 8
    key_sizes = PrivateKey.key_sizes
    default_size = 4096
    symmetric_key_size = 256

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
            self._key_id = digest.finalize()[:self.id_length].hex()
        return self._key_id

    @property
    def public_key(self) -> PublicKEK:
        if not hasattr(self, "_public_key"):
            self._public_key = PublicKEK(self._private_key.public_key)
        return self._public_key

    @classmethod
    @raises(exceptions.KeyGenerationError)
    def generate(cls: Type[PrivateKEK],
                 key_size: Optional[int] = None) -> PrivateKEK:
        private_key = PrivateKey.generate(key_size or cls.default_size)
        return cls(private_key)

    @classmethod
    @raises(exceptions.KeyLoadingError)
    def load(cls: Type[PrivateKEK], serialized_key: bytes,
             password: Optional[bytes] = None) -> PrivateKEK:
        private_key = PrivateKey.load(serialized_key, password)
        return cls(private_key)

    @raises(exceptions.KeySerializationError)
    def serialize(self, password: Optional[bytes] = None) -> bytes:
        return self._private_key.serialize(password)

    @raises(exceptions.EncryptionError)
    def encrypt(self, data: bytes) -> bytes:
        return self.public_key.encrypt(data)

    @raises(exceptions.DecryptionError)
    def decrypt(self, encrypted_data: bytes) -> bytes:
        encryption_id = encrypted_data[:self.id_length]
        if encryption_id != bytes.fromhex(self.key_id):
            raise exceptions.DecryptionError(
                "Can't decrypt this data because it "
                "was encrypted with key that has different id.")
        key_data_end_position = self.id_length + self.key_size // 8
        encrypted_key_data = encrypted_data[
            self.id_length:key_data_end_position
        ]
        symmetric_key_data = self._private_key.decrypt(encrypted_key_data)
        symmetric_key_bytes = symmetric_key_data[:self.symmetric_key_size//8]
        symmetric_key_iv = symmetric_key_data[self.symmetric_key_size//8:]
        symmetric_key = SymmetricKey(symmetric_key_bytes, symmetric_key_iv)
        return symmetric_key.decrypt(
            encrypted_data[key_data_end_position:])

    @raises(exceptions.SingingError)
    def sign(self, data: bytes) -> bytes:
        return self._private_key.sign(data)

    @raises(exceptions.VerificationError)
    def verify(self, signature: bytes, data: bytes) -> bool:
        return self._private_key.verify(signature, data)


class PublicKEK(BasePublicKey):
    algorithm = PrivateKEK.algorithm
    id_length = PrivateKEK.id_length
    symmetric_key_size = PrivateKEK.symmetric_key_size

    def __init__(self, public_key_object: PublicKey) -> None:
        self._public_key = public_key_object

    @property
    def key_size(self) -> int:
        return self._public_key.key_size

    @property
    def key_id(self) -> str:
        if not hasattr(self, "_key_id"):
            digest = hashes.Hash(hashes.SHA256())
            digest.update(self._public_key.serialize())
            self._key_id = digest.finalize()[:self.id_length].hex()
        return self._key_id

    @classmethod
    @raises(exceptions.KeyLoadingError)
    def load(cls: Type[PublicKEK], serialized_key: bytes) -> PublicKEK:
        public_key = PublicKey.load(serialized_key)
        return cls(public_key)

    @raises(exceptions.KeySerializationError)
    def serialize(self) -> bytes:
        return self._public_key.serialize()

    @raises(exceptions.EncryptionError)
    def encrypt(self, data: bytes) -> bytes:
        symmetric_key = SymmetricKey.generate(self.symmetric_key_size)
        encrypted_part = symmetric_key.encrypt(data)
        encrypted_key_data = self._public_key.encrypt(
            symmetric_key.key+symmetric_key.iv)
        return bytes.fromhex(self.key_id) + encrypted_key_data + encrypted_part

    @raises(exceptions.VerificationError)
    def verify(self, signature: bytes, data: bytes) -> bool:
        return self._public_key.verify(signature, data)
