import io
from abc import ABCMeta, abstractmethod
from typing import Iterator

from cryptography.hazmat.primitives.asymmetric import rsa

from .. import constants
from ..constants import KekAlgorithmVersion


class DecryptionBackend(metaclass=ABCMeta):
    version: KekAlgorithmVersion

    def __init__(self, data: bytes, private_key: rsa.RSAPrivateKey) -> None:
        self._data = data
        self._private_key = private_key

    @property
    def key_id(self) -> bytes:
        return self._data[constants.KEY_ID_SLICE]

    @abstractmethod
    def decrypt(self) -> bytes: ...


class StreamDecryptionBackend(metaclass=ABCMeta):
    version: KekAlgorithmVersion

    def __init__(
        self,
        key_id: bytes,
        buffer: io.BufferedIOBase,
        private_key: rsa.RSAPrivateKey,
    ) -> None:
        self._key_id = key_id
        self._buffer = buffer
        self._private_key = private_key

    @property
    def key_id(self) -> bytes:
        return self._key_id

    @abstractmethod
    def decrypt(self) -> Iterator[bytes]: ...
