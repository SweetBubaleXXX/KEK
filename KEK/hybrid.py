from __future__ import annotations

from typing import Optional, Type

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
    id_length : int
        Length of id bytes.
    key_sizes : iterable
        Available sizes (in bits) for key.
    default_size : int
        Default key size.
    symmetric_key_size : int
        Size (in bits) of Symmetric Key used for encryption.
    """
    algorithm = f"{PrivateKey.algorithm}+{SymmetricKey.algorithm}"
    version = int(__version__[0])
    id_length = 8
    key_sizes = PrivateKey.key_sizes
    default_size = 4096
    symmetric_key_size = 256

    def __init__(self, private_key_object: PrivateKey) -> None:
        """
        Parameters
        ----------
        private_key_object : PrivateKey
        """
        self._private_key = private_key_object

    @property
    def key_size(self) -> int:
        """Private KEK size in bits."""
        return self._private_key.key_size

    @property
    def key_id(self) -> bytes:
        """Id bytes for this key (key pair)."""
        if not hasattr(self, "_key_id"):
            digest = hashes.Hash(hashes.SHA256())
            digest.update(self._private_key.public_key.serialize())
            self._key_id = digest.finalize()[:self.id_length]
        return self._key_id

    @property
    def public_key(self) -> PublicKEK:
        """Public KEK object for this Private KEK."""
        if not hasattr(self, "_public_key"):
            self._public_key = PublicKEK(self._private_key.public_key)
        return self._public_key

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
        Encrypted bytes.

        Raises
        ------
        EncryptionError
        """
        return self.public_key.encrypt(data)

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

        Raises
        ------
        DecryptionError
        """
        encryption_id = encrypted_data[:self.id_length]
        if encryption_id != self.key_id:
            raise exceptions.DecryptionError(
                "Can't decrypt this data. "
                "Maybe it was encrypted with key that has different id.")
        key_version = encrypted_data[-1]
        if key_version != self.version:
            raise exceptions.DecryptionError(
                "Can't decrypt this data because it "
                "was encrypted with different version of key. "
                f"Your key version - '{self.version}'. "
                f"Data is encrypted with version '{key_version}' of key.")
        key_data_end_position = self.id_length + self.key_size // 8
        encrypted_key_data = encrypted_data[
            self.id_length:key_data_end_position
        ]
        symmetric_key_data = self._private_key.decrypt(encrypted_key_data)
        symmetric_key_bytes = symmetric_key_data[:self.symmetric_key_size//8]
        symmetric_key_iv = symmetric_key_data[self.symmetric_key_size//8:]
        symmetric_key = SymmetricKey(symmetric_key_bytes, symmetric_key_iv)
        return symmetric_key.decrypt(
            encrypted_data[key_data_end_position:-1])

    @raises(exceptions.SigningError)
    def sign(self, data: bytes) -> bytes:
        """Sign byte data.

        Parameters
        ----------
        data : bytes
            Byte data to sign.

        Returns
        -------
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
    id_length : int
        Length of id bytes.
    symmetric_key_size : int
        Size (in bits) of Symmetric Key used for encryption.
    """
    algorithm = PrivateKEK.algorithm
    version = PrivateKEK.version
    id_length = PrivateKEK.id_length
    symmetric_key_size = PrivateKEK.symmetric_key_size

    def __init__(self, public_key_object: PublicKey) -> None:
        """
        Parameters
        ----------
        public_key_object : PublicKey
        """
        self._public_key = public_key_object

    @property
    def key_size(self) -> int:
        """Public KEK size in bits."""
        return self._public_key.key_size

    @property
    def key_id(self) -> bytes:
        """Id bytes for this key (key pair)."""
        if not hasattr(self, "_key_id"):
            digest = hashes.Hash(hashes.SHA256())
            digest.update(self._public_key.serialize())
            self._key_id = digest.finalize()[:self.id_length]
        return self._key_id

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
        Encrypted bytes.

        Raises
        ------
        EncryptionError
        """
        symmetric_key = SymmetricKey.generate(self.symmetric_key_size)
        encrypted_part = symmetric_key.encrypt(data)
        encrypted_key_data = self._public_key.encrypt(
            symmetric_key.key+symmetric_key.iv)
        return (self.key_id +
                encrypted_key_data +
                encrypted_part +
                self.version.to_bytes(1, "big"))

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
        True if signature matches, otherwise False.

        Raises
        ------
        VerificationError
        """
        return self._public_key.verify(signature, data)
