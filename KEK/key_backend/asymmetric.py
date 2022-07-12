from __future__ import annotations

from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import (RSAPrivateKey,
                                                           RSAPublicKey)

from .base import BasePrivateKey, BasePublicKey


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
    algorithm = "RSA"
    encoding = serialization.Encoding.PEM
    format = serialization.PrivateFormat.PKCS8
    key_sizes = (2048, 3072, 4096)
    default_size = 2048

    def __init__(self, private_key_object: RSAPrivateKey) -> None:
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
    def generate(key_size: Optional[int] = None) -> PrivateKey:
        """Generate Public Key with set key size.

        Parameters
        ----------
        key_size : int
            Size of key in bits.

        Returns
        -------
        Private Key object.
        """
        if key_size and key_size not in PrivateKey.key_sizes:
            raise ValueError
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size or PrivateKey.default_size
        )
        return PrivateKey(private_key)

    @classmethod
    def load(serialized_key: bytes,
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
        """
        private_key = serialization.load_pem_private_key(
            serialized_key,
            password
        )
        return PrivateKey(private_key)

    def serialize(self, password: Optional[bytes] = None) -> bytes:
        """Serialize Private Key. Can be encrypted with password.

        Parameters
        ----------
        password : bytes, optional
            Password for key encryption.

        Returns
        -------
        PEM encoded serialized Private Key.
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

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt byte data with Public Key generated for this Private Key."""
        return self.public_key.encrypt(data)

    def decrypt(self, encrypted_data: bytes) -> bytes:
        """Decrypt byte data."""
        return self._private_key.decrypt(
            encrypted_data,
            padding=PrivateKey.encryption_padding
        )

    def sign(self, data: bytes) -> bytes:
        """Sign byte data."""
        return self._private_key.sign(
            data,
            padding=PrivateKey.signing_padding,
            algorithm=PrivateKey.signing_hash_algorithm
        )

    def verify(self, signature: bytes, data: bytes) -> bool:
        """Verify sighned data with Public Key generated for this Private Key."""
        return self.public_key.verify(signature, data)


class PublicKey(BasePublicKey, PaddingMixin):
    algorithm = PrivateKey.algorithm
    encoding = PrivateKey.encoding
    format = serialization.PublicFormat.SubjectPublicKeyInfo

    def __init__(self, public_key_object: RSAPublicKey) -> None:
        self._public_key = public_key_object

    @property
    def key_size(self) -> int:
        """Public Key size in bits."""
        return self._public_key.key_size

    @classmethod
    def load(serialized_key: bytes) -> PublicKey:
        """Load Public Key from PEM encoded serialized byte data.

        Parameters
        ----------
        serialized_key : bytes
            Encoded key.

        Returns
        -------
        Public Key object.
        """
        public_key = serialization.load_pem_public_key(serialized_key)
        return PublicKey(public_key)

    def serialize(self) -> bytes:
        """Serialize Public Key.

        Returns
        -------
        PEM encoded serialized Public Key.
        """
        return self._public_key.public_bytes(
            encoding=PublicKey.encoding,
            format=PublicKey.format
        )

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt byte data using this Public Key."""
        return self._public_key.encrypt(
            data,
            padding=PublicKey.encryption_padding
        )

    def verify(self, signature: bytes, data: bytes) -> bool:
        """Verify sighned data with this Public Key.

        Returns
        -------
        True if signature matches, otherwise False.
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
