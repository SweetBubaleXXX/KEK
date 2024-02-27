import io
import os
from typing import Iterator, Self

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, CipherContext, modes
from cryptography.hazmat.primitives.ciphers.algorithms import AES256
from cryptography.hazmat.primitives.padding import PKCS7

from .. import constants, exceptions
from ..exceptions import raises
from .decryption import DecryptionBackend
from .encryption import EncryptionBackend

SYMMETRIC_KEY_LENGTH = 32
SYMMETRIC_BLOCK_LENGTH = 16
_SYMMETRIC_PADDING = PKCS7(SYMMETRIC_BLOCK_LENGTH * 8)


def _add_padding(block: bytes) -> bytes:
    padder = _SYMMETRIC_PADDING.padder()
    return padder.update(block) + padder.finalize()


class _StreamEncryptionIterator:
    def __init__(
        self,
        encryptor: CipherContext,
        buffer: io.BufferedIOBase,
        chunk_length: int,
    ) -> None:
        self._encryptor = encryptor
        self._buffer = buffer
        self._chunk_length = chunk_length
        self._finalized = False

    def __iter__(self) -> Self:
        return self

    def __next__(self) -> bytes:
        if self._finalized:
            raise StopIteration()
        chunk = self._buffer.read(self._chunk_length)
        if len(chunk) == SYMMETRIC_BLOCK_LENGTH:
            return self._encryptor.update(chunk)
        last_chunk = _add_padding(chunk)
        return self._encryptor.update(last_chunk) + self._encryptor.finalize()


class Encryptor(EncryptionBackend):
    version = 1

    def __init__(
        self,
        key_id: bytes,
        public_key: RSAPublicKey,
    ) -> None:
        super().__init__(key_id, public_key)
        self._symmetric_key = os.urandom(SYMMETRIC_KEY_LENGTH)
        self._initialization_vector = os.urandom(SYMMETRIC_BLOCK_LENGTH)
        self._cipher = Cipher(
            AES256(self._symmetric_key),
            modes.CBC(self._initialization_vector),
        )

    @raises(exceptions.EncrytionError)
    def get_metadata(self) -> bytes:
        header = self.get_header()
        symmetric_key = self._symmetric_key + self._initialization_vector
        encrypted_symmetric_key = self._public_key.encrypt(
            symmetric_key,
            constants.ASYMMETRIC_ENCRYPTION_PADDING,
        )
        return header + encrypted_symmetric_key

    @raises(exceptions.EncrytionError)
    def encrypt(self, body: bytes) -> bytes:
        encryptor = self._cipher.encryptor()
        padded_body = _add_padding(body)
        return encryptor.update(padded_body) + encryptor.finalize()

    def encrypt_stream(
        self,
        buffer: io.BufferedIOBase,
        *,
        chunk_length: int = constants.CHUNK_LENGTH,
    ) -> Iterator[bytes]:
        encryptor = self._cipher.encryptor()
        chunk = buffer.read(chunk_length)
        while len(chunk) == chunk_length:
            yield encryptor.update(chunk)
            chunk = buffer.read(chunk_length)
        last_chunk = _add_padding(chunk)
        yield encryptor.update(last_chunk) + encryptor.finalize()


class Decryptor(DecryptionBackend):
    pass
