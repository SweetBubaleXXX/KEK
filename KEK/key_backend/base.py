from __future__ import annotations

from abc import ABC, abstractmethod


class BaseSymmetricKey(ABC):
    algorithm: str

    @abstractmethod
    def __init__(self, key: bytes, iv: bytes) -> None:
        pass

    @property
    @abstractmethod
    def key_size(self) -> int:
        pass

    @property
    @abstractmethod
    def key(self) -> bytes:
        pass

    @property
    @abstractmethod
    def iv(self) -> bytes:
        pass

    @classmethod
    @abstractmethod
    def generate(key_size: int) -> BaseSymmetricKey:
        pass

    @abstractmethod
    def encrypt(self, data: bytes) -> bytes:
        pass

    @abstractmethod
    def decrypt(self, encrypted_data: bytes) -> bytes:
        pass


class BasePrivateKey(ABC):
    algorithm: str

    @abstractmethod
    def __init__(self, public_key_object: object) -> None:
        pass

    @abstractmethod
    def __init__(self, private_key_object: object) -> None:
        pass

    @property
    @abstractmethod
    def key_size(self) -> int:
        pass

    @property
    @abstractmethod
    def public_key(self) -> BasePublicKey:
        pass

    @classmethod
    @abstractmethod
    def generate(key_size: int) -> BasePrivateKey:
        pass

    @classmethod
    @abstractmethod
    def load(serialized_key: bytes, password: bytes) -> BasePrivateKey:
        pass

    @abstractmethod
    def serialize(self, password: bytes) -> bytes:
        pass

    @abstractmethod
    def encrypt(self, data: bytes) -> bytes:
        pass

    @abstractmethod
    def decrypt(self, encrypted_data: bytes) -> bytes:
        pass

    @abstractmethod
    def sign(self, data: bytes) -> bytes:
        pass

    @abstractmethod
    def verify(self, signature: bytes, data: bytes) -> bool:
        pass


class BasePublicKey(ABC):
    algorithm: str

    @property
    @abstractmethod
    def key_size(self) -> int:
        pass

    @classmethod
    @abstractmethod
    def load(serialized_key: bytes) -> BasePublicKey:
        pass

    @abstractmethod
    def serialize(self) -> bytes:
        pass

    @abstractmethod
    def encrypt(self, data: bytes) -> bytes:
        pass

    @abstractmethod
    def verify(self, signature: bytes, data: bytes) -> bool:
        pass
