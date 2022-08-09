"""Module with symmetric key class."""

from __future__ import annotations

import os
from typing import Optional, Type, Union

from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.padding import PKCS7

from . import exceptions
from .base import BaseSymmetricKey
from .exceptions import raises


class SymmetricKey(BaseSymmetricKey):
    """Provides symmetric encryption with auto padding.

    Attributes
    ----------
    algorthm : str
        Name of encryption algorithm.
    padding : str
        Name of padding standart.
    key_sizes : iterable
        Available sizes (in bits) for key.
    block_size : int
        Encryption block size in bits.
    """
    algorithm = "AES-CBC"
    padding = "PKCS7"
    key_sizes = (128, 192, 256)
    block_size = 128

    @raises(exceptions.KeyLoadingError)
    def __init__(self, key: bytes, iv: bytes) -> None:
        """
        Parameters
        ----------
        key : bytes
        iv : bytes
        """
        if (len(key)*8 not in self.key_sizes or
                len(iv)*8 != self.block_size):
            raise exceptions.KeyLoadingError(
                f"Invalid key/iv size for {self.algorithm} algorithm. "
                f"Should be one of {self.key_sizes}.")
        self._key = key
        self._iv = iv
        self._prev_encryption_block: Union[bytes, None] = None
        self._prev_decryption_block: Union[bytes, None] = None

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

    def __create_cipher(self, key: bytes, iv: bytes) -> Cipher:
        """Create Cipher object."""
        return Cipher(AES(key), modes.CBC(iv))

    def __add_padding(self, data: bytes) -> bytes:
        """Add padding to byte data with uncertain length."""
        padder = PKCS7(self.block_size).padder()
        return padder.update(data) + padder.finalize()

    def __remove_padding(self, padded_data: bytes) -> bytes:
        """Return unpadded byte data."""
        unpadder = PKCS7(self.block_size).unpadder()
        return unpadder.update(padded_data) + unpadder.finalize()

    def __encrypt_raw(self, data: bytes,
                      prev_block: Optional[bytes] = None) -> bytes:
        """Encrypt byte data using cipher.

        Length of data must be multiple of block size.
        Previous block is used when creating cipher.
        If no previous block specified, iv is used.

        """
        cipher = self.__create_cipher(self._key, prev_block or self._iv)
        encryptor = cipher.encryptor()
        return encryptor.update(data) + encryptor.finalize()

    def __decrypt_raw(self, encrypted_data: bytes,
                      prev_block: Optional[bytes] = None) -> bytes:
        """Decrypt byte data using cipher.

        Length of data must be multiple of block size.
        Previous block is used when creating cipher.
        If no previous block specified, iv is used.

        """
        cipher = self.__create_cipher(self._key, prev_block or self._iv)
        decryptor = cipher.decryptor()
        return decryptor.update(encrypted_data) + decryptor.finalize()

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
        SymmetricKey
            Symmetric Key object.

        Raises
        ------
        KeyGenerationError
        """
        key = os.urandom(key_size // 8)
        iv = os.urandom(cls.block_size // 8)
        return cls(key, iv)

    @raises(exceptions.EncryptionError)
    def encrypt(self, data: bytes) -> bytes:
        """Encrypt byte data with adding padding.

        Parameters
        ----------
        data : bytes
            Byte data to encrypt.

        Returns
        -------
        bytes
            Encrypted data.

        Raises
        ------
        EncryptionError
        """
        padded_data = self.__add_padding(data)
        return self.__encrypt_raw(padded_data)

    @raises(exceptions.EncryptionError)
    def encrypt_chunk(self, data: bytes, is_last: bool = False) -> bytes:
        """Encrypt piece of data.

        Caches last block of encrypted data,
        which will be used in the following call.
        Multiple calls will generate sequence of connected chunks.
        Sequence of chunks can be decrypted as entirely encrypted byte data.

        Parameters
        ----------
        data : bytes
            Byte data to encrypt.
            Length of input bytes must be multiple of block's length.
        is_last : bool
            If True, adds padding to the last block of data, and
            the following call will use iv instead of previous block.

        Returns
        -------
        bytes
            Encrypted data.

        Raises
        ------
        EncryptionError
        """
        if is_last:
            data = self.__add_padding(data)
        encrypted_data = self.__encrypt_raw(data, self._prev_encryption_block)
        if is_last:
            self._prev_encryption_block = None
        else:
            self._prev_encryption_block = encrypted_data[-self.block_size//8:]
        return encrypted_data

    @raises(exceptions.DecryptionError)
    def decrypt(self, encrypted_data: bytes) -> bytes:
        """Decrypt padded byte data.

        Parameters
        ----------
        encrypted_data : bytes
            Byte data (encrypted with padding) to decrypt.

        Returns
        -------
        bytes
            Decrypted data.

        Raises
        ------
        DecryptionError
        """
        decrypted_data = self.__decrypt_raw(encrypted_data)
        return self.__remove_padding(decrypted_data)

    @raises(exceptions.DecryptionError)
    def decrypt_chunk(self, encrypted_data: bytes,
                      is_last: bool = False) -> bytes:
        """Decrypt piece of data.

        Caches last block of encrypted data,
        which will be used in the following call.
        All pieces must be parts of encrypted data
        and be given in the correct order.

        Parameters
        ----------
        encrypted_data : bytes
            Byte data to decrypt.
            Length of input bytes must be multiple of block's length.
        is_last : bool
            If True, removes padding from the last block of data, and
            the following call will use iv instead of previous block.

        Returns
        -------
        bytes
            Decrypted data.

        Raises
        ------
        DecryptionError
        """
        decrypted_data = self.__decrypt_raw(
            encrypted_data,
            self._prev_decryption_block
        )
        if is_last:
            self._prev_decryption_block = None
            return self.__remove_padding(decrypted_data)
        self._prev_decryption_block = encrypted_data[-self.block_size//8:]
        return decrypted_data
