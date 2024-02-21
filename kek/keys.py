from io import BufferedIOBase
from typing import AsyncIterable, Iterable, Self

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, utils

from . import constants, exceptions
from .exceptions import raises


class PublicKey:
    def __init__(self, key: rsa.RSAPublicKey) -> None:
        self._key = key

    @classmethod
    def load(cls, serialized_key: bytes) -> Self:
        public_key = serialization.load_pem_public_key(serialized_key)
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise
        return cls(public_key)

    def verify(self, signature: bytes, message: bytes) -> bool:
        return self._signature_is_valid(signature, message)

    def verify_stream(
        self,
        signature: bytes,
        message: BufferedIOBase,
        chunk_size: int = constants.CHUNK_SIZE,
    ) -> bool:
        hasher = hashes.Hash(constants.SIGNATURE_HASH_ALGORITHM)
        while chunk := message.read(chunk_size):
            hasher.update(chunk)
        digest = hasher.finalize()
        return self._signature_is_valid(
            signature,
            digest,
            utils.Prehashed(constants.SIGNATURE_HASH_ALGORITHM),
        )

    def verify_iterable(self, signature: bytes, message: Iterable[bytes]) -> bool:
        hasher = hashes.Hash(constants.SIGNATURE_HASH_ALGORITHM)
        for chunk in message:
            hasher.update(chunk)
        digest = hasher.finalize()
        return self._signature_is_valid(
            signature,
            digest,
            utils.Prehashed(constants.SIGNATURE_HASH_ALGORITHM),
        )

    async def verify_async_iterable(
        self,
        signature: bytes,
        message: AsyncIterable[bytes],
    ) -> bool:
        hasher = hashes.Hash(constants.SIGNATURE_HASH_ALGORITHM)
        async for chunk in message:
            hasher.update(chunk)
        digest = hasher.finalize()
        return self._signature_is_valid(
            signature,
            digest,
            utils.Prehashed(constants.SIGNATURE_HASH_ALGORITHM),
        )

    def _signature_is_valid(
        self,
        signature: bytes,
        message: bytes,
        hash_algorithm: (
            utils.Prehashed | hashes.HashAlgorithm
        ) = constants.SIGNATURE_HASH_ALGORITHM,
    ) -> bool:
        try:
            self._key.verify(
                signature,
                message,
                padding=constants.SIGNATURE_PADDING,
                algorithm=hash_algorithm,
            )
        except InvalidSignature:
            return False
        return True


class KeyPair:
    def __init__(self, private_key: rsa.RSAPrivateKey) -> None:
        self._rsa_private_key = private_key
        self._public_key = PublicKey(private_key.public_key())

    @property
    def key_size(self) -> int:
        return self._rsa_private_key.key_size

    @property
    def public_key(self) -> PublicKey:
        return self._public_key

    @classmethod
    @raises(exceptions.KeyGenerationError)
    def generate(cls, key_size: constants.KEY_SIZE = 2048) -> Self:
        if key_size not in constants.KEY_SIZES:
            raise ValueError("Invalid key size")
        rsa_private_key = rsa.generate_private_key(
            constants.RSA_PUBLIC_EXPONENT,
            key_size,
        )
        return cls(rsa_private_key)

    @classmethod
    @raises(exceptions.KeyLoadingError)
    def load(cls, serialized_key: bytes, password: bytes | None = None) -> Self:
        private_key = serialization.load_pem_private_key(serialized_key, password)
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise exceptions.KeyLoadingError("Not RSA private key")
        return cls(private_key)
