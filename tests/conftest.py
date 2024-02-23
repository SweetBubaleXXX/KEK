from base64 import b64decode
from typing import AsyncIterator

import pytest

from kek import KeyPair, PublicKey

from . import constants


@pytest.fixture
def key_id():
    return constants.KEY_ID


@pytest.fixture
def key_size():
    return constants.KEY_SIZE


@pytest.fixture
def key_encryption_password():
    return constants.KEY_ENCRYPTION_PASSWORD


@pytest.fixture
def serialized_private_key():
    return constants.SERIALIZED_PRIVATE_KEY


@pytest.fixture
def serialized_public_key():
    return constants.SERIALIZED_PUBLIC_KEY


@pytest.fixture
def encrypted_private_key():
    return constants.ENCRYPTED_PRIVATE_KEY


@pytest.fixture
def message_for_signing():
    return constants.MESSAGE_FOR_SIGNING


@pytest.fixture
def message_signature():
    return b64decode(constants.MESSAGE_SIGNATURE_ENCODED)


@pytest.fixture
def key_pair(serialized_private_key: bytes):
    return KeyPair.load(serialized_private_key)


@pytest.fixture
def public_key(serialized_public_key: bytes):
    return PublicKey.load(serialized_public_key)


@pytest.fixture
def async_iterator():
    async def generator() -> AsyncIterator[bytes]:
        for _ in range(5):
            yield b"chunk"

    return generator()
