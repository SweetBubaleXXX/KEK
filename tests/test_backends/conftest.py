import functools
import io
from typing import Callable

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from gnukek.backends.v1 import Decryptor, Encryptor, StreamDecryptor
from tests import constants


@pytest.fixture
def v1_encryptor(serialized_public_key):
    public_key = serialization.load_pem_public_key(serialized_public_key)
    assert isinstance(public_key, rsa.RSAPublicKey)
    return Encryptor(key_id=constants.KEY_ID, public_key=public_key)


@pytest.fixture
def v1_decryptor_factory(serialized_private_key) -> Callable[[bytes], Decryptor]:
    private_key = serialization.load_pem_private_key(
        serialized_private_key, password=None
    )
    assert isinstance(private_key, rsa.RSAPrivateKey)
    return functools.partial(Decryptor, private_key=private_key)


@pytest.fixture
def v1_stream_decryptor_factory(
    serialized_private_key,
) -> Callable[[io.BufferedIOBase], StreamDecryptor]:
    private_key = serialization.load_pem_private_key(
        serialized_private_key, password=None
    )
    assert isinstance(private_key, rsa.RSAPrivateKey)
    return functools.partial(StreamDecryptor, private_key=private_key)
