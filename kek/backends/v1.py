import io
import os
from typing import Iterator, Self

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, CipherContext, modes
from cryptography.hazmat.primitives.ciphers.algorithms import AES256
from cryptography.hazmat.primitives.padding import PKCS7

from kek.backends.decryption import (
    DecryptionBackend,
    DecryptorBackendFactory,
    StreamDecryptionBackend,
)

from .. import constants, exceptions
from ..exceptions import raises
from .encryption import EncryptionBackend

SYMMETRIC_KEY_LENGTH = 32
SYMMETRIC_BLOCK_LENGTH = 16
_SYMMETRIC_PADDING = PKCS7(SYMMETRIC_BLOCK_LENGTH * 8)


def _add_padding(block: bytes) -> bytes:
    padder = _SYMMETRIC_PADDING.padder()
    return padder.update(block) + padder.finalize()


def _remove_padding(block: bytes) -> bytes:
    unpadder = _SYMMETRIC_PADDING.unpadder()
    return unpadder.update(block) + unpadder.finalize()


def _get_aes_cipher(symmetric_key: bytes, initialization_vector: bytes) -> Cipher:
    """Return an AES cipher in CBC mode."""
    return Cipher(
        AES256(symmetric_key),
        modes.CBC(initialization_vector),
    )


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
            raise StopIteration("Encryption finalized")

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
        self._cipher = _get_aes_cipher(self._symmetric_key, self._initialization_vector)

    @raises(exceptions.EncryptionError)
    def get_metadata(self) -> bytes:
        header = self.get_header()
        symmetric_key_with_iv = self._symmetric_key + self._initialization_vector
        encrypted_symmetric_key = self._public_key.encrypt(
            symmetric_key_with_iv,
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
    version = 1

    def __init__(self, data: bytes, private_key: RSAPrivateKey) -> None:
        super().__init__(data, private_key)
        self._metadata_length = self._private_key.key_size // 8
        self._metadata_start_position = constants.KEY_ID_SLICE.stop
        self._metadata_end_position = (
            self._metadata_start_position + self._metadata_length
        )

    @raises(exceptions.DecryptionError)
    def decrypt(self) -> bytes:
        decrypted_metadata = self._decrypt_metadata()
        symmetric_cipher = self._create_cipher_from_metadata(decrypted_metadata)
        symmetric_decryptor = symmetric_cipher.decryptor()
        decrypted_data = (
            symmetric_decryptor.update(self._data[self._metadata_end_position :])
            + symmetric_decryptor.finalize()
        )
        return _remove_padding(decrypted_data)

    def _decrypt_metadata(self) -> bytes:
        encrypted_metadata = self._data[
            self._metadata_start_position : self._metadata_end_position
        ]

        return self._private_key.decrypt(
            encrypted_metadata,
            constants.ASYMMETRIC_ENCRYPTION_PADDING,
        )

    def _create_cipher_from_metadata(self, decrypted_metadata: bytes) -> Cipher:
        symmetric_key = decrypted_metadata[:SYMMETRIC_KEY_LENGTH]
        initialization_vector = decrypted_metadata[SYMMETRIC_KEY_LENGTH:]

        return _get_aes_cipher(symmetric_key, initialization_vector)


class StreamDecryptor(StreamDecryptionBackend):
    pass


class DecryptorFactory(DecryptorBackendFactory):
    version = 1

    @staticmethod
    def get_decryptor(data: bytes, private_key: RSAPrivateKey) -> Decryptor:
        return Decryptor(data, private_key)

    @staticmethod
    def get_stream_decryptor(
        buffer: io.BufferedIOBase, private_key: RSAPrivateKey
    ) -> StreamDecryptor:
        pass
