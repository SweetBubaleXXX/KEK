import pytest

from kek.keys import PublicKey


@pytest.fixture
def v1_encryptor(public_key: PublicKey):
    return public_key.get_encryptor(version=1)
