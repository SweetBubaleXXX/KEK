"""Module with hybrid key classes."""

from __future__ import annotations

import os
from io import BufferedIOBase
from typing import Generator, Optional, Type, Union

from cryptography.hazmat.primitives import hashes

from . import __version__, exceptions
from .asymmetric import PrivateKey, PublicKey
from .base import BasePrivateKey, BasePublicKey
from .exceptions import raises
from .symmetric import SymmetricKey


class PrivateKEK(BasePrivateKey):
    """Provides hybrid (asymmetric + symmetric) encryption.

    This key is based on Private Key and Symmetric Key.

    Attributes
    ----------
    algorthm : str
        Name of encryption algorithm.
    version : int
        Version of key.
        Keys with different versions are incompatible.
    version_length : int
        Length of version bytes.
    id_length : int
        Length of id bytes.
    key_sizes : iterable
        Available sizes (in bits) for key.
    default_size : int
        Default key size.
    symmetric_key_size : int
        Size (in bits) of Symmetric Key used for encryption.
    block_size : int
        Encryption block size in bits.
    """
    algorithm = f"{PrivateKey.algorithm}+{SymmetricKey.algorithm}"
    version = int(__version__[0])
    version_length = 1
    id_length = 8
    key_sizes = PrivateKey.key_sizes
    default_size = 4096
    symmetric_key_size = 256
    block_size = SymmetricKey.block_size

    def __init__(self, private_key_object: PrivateKey) -> None:
        """
        Parameters
        ----------
        private_key_object : PrivateKey
        """
        self._private_key = private_key_object
        self._public_key: Union[PublicKEK, None] = None
        self._key_id: Union[bytes, None] = None

    @property
    def key_size(self) -> int:
        """Private KEK size in bits."""
        return self._private_key.key_size

    @property
    def key_id(self) -> bytes:
        """Id bytes for this key (key pair)."""
        if not self._key_id:
            digest = hashes.Hash(hashes.SHA256())
            digest.update(self._private_key.public_key.serialize())
            self._key_id = digest.finalize()[:self.id_length]
        return self._key_id

    @property
    def metadata_length(self) -> int:
        """Length of metadata bytes.

        Metadata consists of key version, key id and encrypted symmetric key.

        """
        return (self.version_length +
                self.id_length +
                self.key_size//8)

    @property
    def public_key(self) -> PublicKEK:
        """Public KEK object for this Private KEK."""
        if not self._public_key:
            self._public_key = PublicKEK(self._private_key.public_key)
        return self._public_key

    def __verify_version(self, encryption_key_version: bytes) -> None:
        """Raise exception if key versions don't match."""
        if int.from_bytes(encryption_key_version, "big") != self.version:
            raise exceptions.DecryptionError(
                "Can't decrypt this data. "
                "Maybe it was encrypted with different version of key. "
                f"Your key version - '{self.version}'. ")

    def __verify_id(self, encryption_key_id: bytes) -> None:
        """Raise exception if provided id doesn't match with current key id."""
        if encryption_key_id != self.key_id:
            raise exceptions.DecryptionError(
                "Can't decrypt this data. "
                "Maybe it was encrypted with key that has different id.")

    def __decrypt_symmetric_key(self, encrypted_key: bytes) -> SymmetricKey:
        """Create Symmetric Key object from encrypted bytes."""
        decrypted_key = self._private_key.decrypt(encrypted_key)
        symmetric_key_bytes = decrypted_key[:self.symmetric_key_size//8]
        symmetric_key_iv = decrypted_key[self.symmetric_key_size//8:]
        return SymmetricKey(symmetric_key_bytes, symmetric_key_iv)

    def __decrypt_metadata(self, meta_bytes: bytes) -> SymmetricKey:
        """Verify key metadata and return Symmetric Key object."""
        self.__verify_version(meta_bytes[:self.version_length])
        id_end_byte_position = self.version_length + self.id_length
        self.__verify_id(meta_bytes[self.version_length:id_end_byte_position])
        return self.__decrypt_symmetric_key(meta_bytes[id_end_byte_position:])

    @classmethod
    @raises(exceptions.KeyGenerationError)
    def generate(cls: Type[PrivateKEK],
                 key_size: Optional[int] = None) -> PrivateKEK:
        """Generate Private KEK with set key size.

        Parameters
        ----------
        key_size : int, optional
            Size of key in bits.

        Returns
        -------
        PrivateKEK
            Private KEK object.

        Raises
        ------
        KeyGenerationError
        """
        private_key = PrivateKey.generate(key_size or cls.default_size)
        return cls(private_key)

    @classmethod
    @raises(exceptions.KeyLoadingError)
    def load(cls: Type[PrivateKEK], serialized_key: bytes,
             password: Optional[bytes] = None) -> PrivateKEK:
        """Load Private KEK from PEM encoded serialized byte data.

        Parameters
        ----------
        serialized_key : bytes
            Encoded key.
        password : bytes, optional
            Password for encrypted serialized key.

        Returns
        -------
        PrivateKEK
            Private KEK object.

        Raises
        ------
        KeyLoadingError
        """
        private_key = PrivateKey.load(serialized_key, password)
        return cls(private_key)

    @raises(exceptions.KeySerializationError)
    def serialize(self, password: Optional[bytes] = None) -> bytes:
        """Serialize Private KEK. Can be encrypted with password.

        Parameters
        ----------
        password : bytes, optional
            Password for key encryption.

        Returns
        -------
        bytes
            PEM encoded serialized Private KEK.

        Raises
        ------
        KeySerializationError
        """
        return self._private_key.serialize(password)

    @raises(exceptions.EncryptionError)
    def encrypt(self, data: bytes) -> bytes:
        """Encrypt byte data with Public KEK generated for this Private KEK.

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
        return self.public_key.encrypt(data)

    @raises(exceptions.EncryptionError)
    def encrypt_chunks(
            self, binary_stream: BufferedIOBase,
            chunk_length: int = 1024*1024) -> Generator[bytes, None, None]:
        """Chunk encryption generator.

        Parameters
        ----------
        binary_stream : BufferedIOBase
            Buffered binary stream.
            Could be either io.BufferedReader or io.BytesIO.
        chunk_length : int
            Length (bytes) of chunk to encrypt.

        Yields
        ------
        bytes
            Encrypted bytes.
            Length of encrypted bytes is the same as chunk's length.

        Raises
        ------
        EncryptionError
        """
        return self.public_key.encrypt_chunks(binary_stream, chunk_length)

    @raises(exceptions.DecryptionError)
    def decrypt(self, encrypted_data: bytes) -> bytes:
        """Decrypt byte data.

        Parameters
        ----------
        encrypted_data : bytes
            Byte data to decrypt.

        Returns
        -------
        bytes
            Decrypted data.

        Raises
        ------
        DecryptionError
        """
        symmetric_key = self.__decrypt_metadata(
            encrypted_data[:self.metadata_length])
        return symmetric_key.decrypt(
            encrypted_data[self.metadata_length:])

    @raises(exceptions.DecryptionError)
    def decrypt_chunks(
            self, binary_stream: BufferedIOBase,
            chunk_length: int = 1024*1024) -> Generator[bytes, None, None]:
        """Chunk decryption generator.

        Parameters
        ----------
        binary_stream : BufferedIOBase
            Buffered binary stream.
            Could be either io.BufferedReader or io.BytesIO.
        chunk_length : int
            Length (bytes) of chunk to encrypt.

        Yields
        ------
        bytes
            Decrypted data.
            Length of decrypted bytes is the same as chunk's length.

        Raises
        ------
        DecryptionError
        """
        binary_stream.seek(0, os.SEEK_END)
        stream_length = binary_stream.tell()
        binary_stream.seek(0, os.SEEK_SET)
        symmetric_key = self.__decrypt_metadata(
            binary_stream.read(self.metadata_length))
        while chunk_length:
            chunk = binary_stream.read(chunk_length)
            if not chunk:
                break
            is_last = binary_stream.tell() == stream_length
            yield symmetric_key.decrypt_chunk(chunk, is_last)

    @raises(exceptions.SigningError)
    def sign(self, data: bytes) -> bytes:
        """Sign byte data.

        Parameters
        ----------
        data : bytes
            Byte data to sign.

        Returns
        -------
        bytes
            Singed byte data.

        Raises
        ------
        SigningError
        """
        return self._private_key.sign(data)

    @raises(exceptions.VerificationError)
    def verify(self, signature: bytes, data: bytes) -> bool:
        """Verify signature with Public KEK generated for this Private KEK.

        Parameters
        ----------
        signature : bytes
            Signed byte data.
        data : bytes
            Original byte data.

        Returns
        -------
        bool
            True if signature matches, otherwise False.

        Raises
        ------
        VerificationError
        """
        return self._private_key.verify(signature, data)


class PublicKEK(BasePublicKey):
    """Provides hybrid (asymmetric + symmetric) encryption via public key.

    This key is based on Private Key and Symmetric Key.

    Attributes
    ----------
    algorthm : str
        Name of encryption algorithm.
    version : int
        Version of key.
        Keys with different versions are incompatible.
    version_length : int
        Length of version bytes.
    id_length : int
        Length of id bytes.
    symmetric_key_size : int
        Size (in bits) of Symmetric Key used for encryption.
    block_size : int
        Encryption block size in bits.
    """
    algorithm = PrivateKEK.algorithm
    version = PrivateKEK.version
    version_length = PrivateKEK.version_length
    id_length = PrivateKEK.id_length
    symmetric_key_size = PrivateKEK.symmetric_key_size
    block_size = PrivateKEK.block_size

    def __init__(self, public_key_object: PublicKey) -> None:
        """
        Parameters
        ----------
        public_key_object : PublicKey
        """
        self._public_key = public_key_object
        self._key_id: Union[bytes, None] = None

    @property
    def key_size(self) -> int:
        """Public KEK size in bits."""
        return self._public_key.key_size

    @property
    def key_id(self) -> bytes:
        """Id bytes for this key (key pair)."""
        if not self._key_id:
            digest = hashes.Hash(hashes.SHA256())
            digest.update(self._public_key.serialize())
            self._key_id = digest.finalize()[:self.id_length]
        return self._key_id

    def __encrypt_symmetric_key(self, symmetric_key: SymmetricKey) -> bytes:
        """Encrypt Symmetric Key data using Public Key."""
        return self._public_key.encrypt(symmetric_key.key+symmetric_key.iv)

    @classmethod
    @raises(exceptions.KeyLoadingError)
    def load(cls: Type[PublicKEK], serialized_key: bytes) -> PublicKEK:
        """Load Public KEK from PEM encoded serialized byte data.

        Parameters
        ----------
        serialized_key : bytes
            Encoded key.

        Returns
        -------
        PublicKEK
            Public KEK object.

        Raises
        ------
        KeyLoadingError
        """
        public_key = PublicKey.load(serialized_key)
        return cls(public_key)

    @raises(exceptions.KeySerializationError)
    def serialize(self) -> bytes:
        """Serialize Public KEK.

        Returns
        -------
        bytes
            PEM encoded serialized Public KEK.

        Raises
        ------
        KeySerializationError
        """
        return self._public_key.serialize()

    @raises(exceptions.EncryptionError)
    def encrypt(self, data: bytes) -> bytes:
        """Encrypt byte data using this Public KEK.

        Parameters
        ----------
        data : bytes
            Byte data to encrypt.

        Returns
        -------
        bytes
            Encrypted bytes.

        Raises
        ------
        EncryptionError
        """
        symmetric_key = SymmetricKey.generate(self.symmetric_key_size)
        encrypted_part = symmetric_key.encrypt(data)
        encrypted_key_data = self.__encrypt_symmetric_key(symmetric_key)
        return (self.version.to_bytes(1, "big") +
                self.key_id +
                encrypted_key_data +
                encrypted_part)

    @raises(exceptions.EncryptionError)
    def encrypt_chunks(
            self, binary_stream: BufferedIOBase,
            chunk_length: int = 1024*1024) -> Generator[bytes, None, None]:
        """Chunk encryption generator.

        Parameters
        ----------
        binary_stream : BufferedIOBase
            Buffered binary stream.
            Could be either io.BufferedReader or io.BytesIO.
        chunk_length : int
            Length (bytes) of chunk to encrypt.

        Yields
        ------
        bytes
            Encrypted bytes.
            Length of encrypted bytes is the same as chunk's length.

        Raises
        ------
        EncryptionError
        """
        symmetric_key = SymmetricKey.generate(self.symmetric_key_size)
        yield (self.version.to_bytes(1, "big") +
               self.key_id +
               self.__encrypt_symmetric_key(symmetric_key))
        while chunk_length:
            chunk = binary_stream.read(chunk_length)
            is_last = (len(chunk) == 0
                       or len(chunk) % (symmetric_key.block_size // 8) > 0)
            yield symmetric_key.encrypt_chunk(chunk, is_last)
            if is_last:
                break

    @raises(exceptions.VerificationError)
    def verify(self, signature: bytes, data: bytes) -> bool:
        """Verify signature data with this Public KEK.

        Parameters
        ----------
        signature : bytes
            Signed byte data.
        data : bytes
            Original byte data.

        Returns
        -------
        bool
            True if signature matches, otherwise False.

        Raises
        ------
        VerificationError
        """
        return self._public_key.verify(signature, data)
