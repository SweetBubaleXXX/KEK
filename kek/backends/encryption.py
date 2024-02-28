import io
from abc import ABCMeta, abstractmethod
from typing import Iterator

from cryptography.hazmat.primitives.asymmetric import rsa

from .. import constants
from ..constants import KekAlgorithmVersion


class EncryptionBackend(metaclass=ABCMeta):
    version: KekAlgorithmVersion

    def __init__(self, key_id: bytes, public_key: rsa.RSAPublicKey) -> None:
        self._key_id = key_id
        self._public_key = public_key

    def get_header(self) -> bytes:
        return self.version.to_bytes() + self._key_id

    @abstractmethod
    def get_metadata(self) -> bytes: ...

    @abstractmethod
    def encrypt(self, body: bytes) -> bytes: ...

    @abstractmethod
    def encrypt_stream(
        self,
        buffer: io.BufferedIOBase,
        *,
        chunk_length: int = constants.CHUNK_LENGTH,
    ) -> Iterator[bytes]: ...
