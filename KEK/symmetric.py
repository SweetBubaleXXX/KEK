from __future__ import annotations

import os
from typing import Type

from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.padding import PKCS7

from . import exceptions
from .base import BaseSymmetricKey
from .exceptions import raises


class SymmetricKey(BaseSymmetricKey):
    algorithm = "AES-CBC"
    padding = "PKCS7"
    key_sizes = (128, 192, 256)
    block_size = 128

    def __init__(self, key: bytes, iv: bytes) -> None:
        if (len(key)*8 not in self.key_sizes or
                len(iv)*8 != self.block_size):
            raise exceptions.KeyGenerationError(
                f"Invalid key/iv size for {self.algorithm} algorithm. "
                f"Should be one of {self.key_sizes}.")
        self._key = key
        self._iv = iv
        self._cipher = Cipher(AES(key), modes.CBC(iv))

    @property
    def key_size(self) -> int:
        """Size of key in bits."""
        return len(self._key) * 8

    @property
    def key(self) -> bytes:
        """Byte data of key."""
        return self._key

    @property
    def iv(self) -> bytes:
        """Byte data of iv."""
        return self._iv

    @classmethod
    @raises(exceptions.KeyGenerationError)
    def generate(cls: Type[SymmetricKey], key_size: int = 256) -> SymmetricKey:
        """Generate Symmetric Key with set key size.

        Parameters
        ----------
        key_size : int
            Size of key in bits.

        Returns
        -------
        Symmetric Key object.
        """
        key = os.urandom(key_size // 8)
        iv = os.urandom(cls.block_size // 8)
        return cls(key, iv)

    @raises(exceptions.EncryptionError)
    def encrypt(self, data: bytes) -> bytes:
        """Encrypt byte data.

        Parameters
        ----------
        data : bytes
            Byte data to encrypt.

        Returns
        -------
        Encrypted bytes.
        """
        padder = PKCS7(self.block_size).padder()
        encryptor = self._cipher.encryptor()
        padded_data = padder.update(data) + padder.finalize()
        return encryptor.update(padded_data) + encryptor.finalize()

    @raises(exceptions.DecryptionError)
    def decrypt(self, encrypted_data: bytes) -> bytes:
        """Decrypt byte data.

        Parameters
        ----------
        encrypted_data : bytes
            Byte data to decrypt.

        Returns
        -------
        Decrypted bytes.
        """
        unpadder = PKCS7(self.block_size).unpadder()
        decryptor = self._cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data)
        decrypted_data += decryptor.finalize()
        return unpadder.update(decrypted_data) + unpadder.finalize()
