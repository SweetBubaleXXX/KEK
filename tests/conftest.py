import pytest

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
