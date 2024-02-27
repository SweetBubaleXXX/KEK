import io
from base64 import b64decode

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
def sample_message():
    return constants.SAMPLE_MESSAGE


@pytest.fixture
def sample_message_buffer(sample_message: bytes):
    return io.BytesIO(sample_message)


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
def v1_encryptor(public_key: PublicKey):
    return public_key.get_encryptor(version=1)
