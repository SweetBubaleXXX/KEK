from __future__ import annotations

from typing import Optional, Type

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from . import exceptions
from .base import BasePrivateKey, BasePublicKey
from .exceptions import raises


class PaddingMixin:
    encryption_padding = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
    signing_padding = padding.PSS(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    )
    signing_hash_algorithm = hashes.SHA256()


class PrivateKey(BasePrivateKey, PaddingMixin):
    """Provides asymmetric encryption.

    Attributes
    ----------
    algorthm : str
        Name of encryption algorithm.
    key_sizes : iterable
        Available sizes (in bits) for key.
    default_size : int
        Default key size in bits.
    """
    algorithm = "RSA"
    encoding = serialization.Encoding.PEM
    format = serialization.PrivateFormat.PKCS8
    key_sizes = (2048, 3072, 4096)
    default_size = 2048

    def __init__(self, private_key_object: rsa.RSAPrivateKey) -> None:
        """
        Parameters
        ----------
        private_key_object : cryptography.hazmat.primitives. ... .RSAPrivateKey
        """
        self._private_key = private_key_object

    @property
    def key_size(self) -> int:
        """Private Key size in bits."""
        return self._private_key.key_size

    @property
    def public_key(self) -> PublicKey:
        """Public Key object for this Private Key."""
        if not hasattr(self, "_public_key"):
            public_key_object = self._private_key.public_key()
            self._public_key = PublicKey(public_key_object)
        return self._public_key

    @classmethod
    @raises(exceptions.KeyGenerationError)
    def generate(cls: Type[PrivateKey],
                 key_size: Optional[int] = None) -> PrivateKey:
        """Generate Private Key with set key size.

        Parameters
        ----------
        key_size : int
            Size of key in bits.

        Returns
        -------
        Private Key object.

        Raises
        ------
        KeyGenerationError
        """
        if key_size and key_size not in cls.key_sizes:
            raise exceptions.KeyGenerationError(
                f"Invalid key size for {cls.algorithm} algorithm. "
                f"Should be one of {cls.key_sizes}.")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size or cls.default_size
        )
        return cls(private_key)

    @classmethod
    @raises(exceptions.KeyLoadingError)
    def load(cls: Type[PrivateKey], serialized_key: bytes,
             password: Optional[bytes] = None) -> PrivateKey:
        """Load Private Key from PEM encoded serialized byte data.

        Parameters
        ----------
        serialized_key : bytes
            Encoded key.
        password : bytes, optional
            Password for encrypted serialized key.

        Returns
        -------
        Private Key object.

        Raises
        ------
        KeyLoadingError
        """
        private_key = serialization.load_pem_private_key(
            serialized_key,
            password
        )
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise exceptions.KeyLoadingError("Invalid key format.")
        return cls(private_key)

    @raises(exceptions.KeySerializationError)
    def serialize(self, password: Optional[bytes] = None) -> bytes:
        """Serialize Private Key. Can be encrypted with password.

        Parameters
        ----------
        password : bytes, optional
            Password for key encryption.

        Returns
        -------
        PEM encoded serialized Private Key.

        Raises
        ------
        KeySerializationError
        """
        if password:
            encryption_algorithm = serialization.BestAvailableEncryption(
                password)
        else:
            encryption_algorithm = serialization.NoEncryption()
        return self._private_key.private_bytes(
            encoding=PrivateKey.encoding,
            format=PrivateKey.format,
            encryption_algorithm=encryption_algorithm
        )

    @raises(exceptions.EncryptionError)
    def encrypt(self, data: bytes) -> bytes:
        """Encrypt byte data with Public Key generated for this Private Key.

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
        return self._private_key.decrypt(
            encrypted_data,
            padding=PrivateKey.encryption_padding
        )

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
        return self._private_key.sign(
            data,
            padding=PrivateKey.signing_padding,
            algorithm=PrivateKey.signing_hash_algorithm
        )

    @raises(exceptions.VerificationError)
    def verify(self, signature: bytes, data: bytes) -> bool:
        """Verify signature with Public Key generated for this Private Key.

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
        return self.public_key.verify(signature, data)


class PublicKey(BasePublicKey, PaddingMixin):
    """Provides asymmetric encryption via public key.

    Attributes
    ----------
    algorthm : str
        Name of encryption algorithm.
    """
    algorithm = PrivateKey.algorithm
    encoding = PrivateKey.encoding
    format = serialization.PublicFormat.SubjectPublicKeyInfo

    def __init__(self, public_key_object: rsa.RSAPublicKey) -> None:
        """
        Parameters
        ----------
        public_key_object : cryptography.hazmat.primitives. ... .RSAPublicKey
        """
        self._public_key = public_key_object

    @property
    def key_size(self) -> int:
        """Public Key size in bits."""
        return self._public_key.key_size

    @classmethod
    @raises(exceptions.KeyLoadingError)
    def load(cls: Type[PublicKey], serialized_key: bytes) -> PublicKey:
        """Load Public Key from PEM encoded serialized byte data.

        Parameters
        ----------
        serialized_key : bytes
            Encoded key.

        Returns
        -------
        Public Key object.

        Raises
        ------
        KeyLoadingError
        """
        public_key = serialization.load_pem_public_key(serialized_key)
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise exceptions.KeyLoadingError("Invalid key format.")
        return cls(public_key)

    @raises(exceptions.KeySerializationError)
    def serialize(self) -> bytes:
        """Serialize Public Key.

        Returns
        -------
        PEM encoded serialized Public Key.

        Raises
        ------
        KeySerializationError
        """
        return self._public_key.public_bytes(
            encoding=PublicKey.encoding,
            format=PublicKey.format
        )

    @raises(exceptions.EncryptionError)
    def encrypt(self, data: bytes) -> bytes:
        """Encrypt byte data using this Public Key.

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
        return self._public_key.encrypt(
            data,
            padding=PublicKey.encryption_padding
        )

    @raises(exceptions.VerificationError)
    def verify(self, signature: bytes, data: bytes) -> bool:
        """Verify signature data with this Public Key.

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
        try:
            self._public_key.verify(
                signature,
                data,
                PublicKey.signing_padding,
                PublicKey.signing_hash_algorithm
            )
        except InvalidSignature:
            return False
        else:
            return True
