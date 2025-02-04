from abc import ABCMeta, abstractmethod
from typing import BinaryIO, Iterator

from cryptography.hazmat.primitives.asymmetric import rsa

from .. import constants
from ..constants import KekAlgorithmVersion


class DecryptionBackend(metaclass=ABCMeta):
    version: KekAlgorithmVersion

    def __init__(self, data: bytes, private_key: rsa.RSAPrivateKey) -> None:
        self._data = data
        self._private_key = private_key

    @abstractmethod
    def decrypt(self) -> bytes: ...


class StreamDecryptionBackend(metaclass=ABCMeta):
    version: KekAlgorithmVersion

    def __init__(
        self,
        buffer: BinaryIO,
        private_key: rsa.RSAPrivateKey,
    ) -> None:
        self._buffer = buffer
        self._private_key = private_key

    @abstractmethod
    def decrypt_stream(
        self,
        *,
        chunk_length: int = constants.CHUNK_LENGTH,
    ) -> Iterator[bytes]: ...


class DecryptionBackendFactory(metaclass=ABCMeta):
    version: KekAlgorithmVersion

    @staticmethod
    @abstractmethod
    def get_decryptor(
        data: bytes, *, private_key: rsa.RSAPrivateKey
    ) -> DecryptionBackend: ...

    @staticmethod
    @abstractmethod
    def get_stream_decryptor(
        buffer: BinaryIO, *, private_key: rsa.RSAPrivateKey
    ) -> StreamDecryptionBackend: ...
