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

    @raises(exceptions.EncryptionError)
    def __next__(self) -> bytes:
        if self._finalized:
            raise StopIteration()

        chunk = self._buffer.read(self._chunk_length)
        if len(chunk) == self._chunk_length:
            return self._encryptor.update(chunk)

        last_chunk = _add_padding(chunk)
        encrypted_last_chunk = (
            self._encryptor.update(last_chunk) + self._encryptor.finalize()
        )
        self._finalized = True
        return encrypted_last_chunk


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

    @raises(exceptions.EncryptionError)
    def get_metadata(self) -> bytes:
        header = self.get_header()
        symmetric_key = self._symmetric_key + self._initialization_vector
        encrypted_symmetric_key = self._public_key.encrypt(
            symmetric_key,
            constants.ASYMMETRIC_ENCRYPTION_PADDING,
        )
        return header + encrypted_symmetric_key

    @raises(exceptions.EncryptionError)
    def encrypt(self, body: bytes) -> bytes:
        encryptor = self._cipher.encryptor()
        padded_body = _add_padding(body)
        return encryptor.update(padded_body) + encryptor.finalize()

    @raises(exceptions.EncryptionError)
    def encrypt_stream(
        self,
        buffer: io.BufferedIOBase,
        *,
        chunk_length: int = constants.CHUNK_LENGTH,
    ) -> Iterator[bytes]:
        if chunk_length % SYMMETRIC_BLOCK_LENGTH:
            raise exceptions.EncryptionError(
                "Chunk length is not multiple of block length"
            )
        encryptor = self._cipher.encryptor()
        return _StreamEncryptionIterator(encryptor, buffer, chunk_length)


class Decryptor(DecryptionBackend):
    pass
