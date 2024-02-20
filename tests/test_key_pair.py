import pytest

from kek import KeyPair, exceptions

from . import constants


def test_load_key():
    loaded_key_pair = KeyPair.load(constants.SERIALIZED_PRIVATE_KEY)
    assert isinstance(loaded_key_pair, KeyPair)


def test_load_unencrypted_key_with_password():
    with pytest.raises(exceptions.KeyLoadingError):
        KeyPair.load(
            constants.SERIALIZED_PRIVATE_KEY,
            constants.PRIVATE_KEY_ENCRYPTION_PASSWORD,
        )


def test_load_encrypted_key_without_password():
    with pytest.raises(exceptions.KeyLoadingError):
        KeyPair.load(constants.ENCRYPTED_PRIVATE_KEY)


def test_generate_key_pair():
    generated_key_pair = KeyPair.generate()
    assert isinstance(generated_key_pair, KeyPair)


def test_generate_key_pair_invalid_key_size():
    with pytest.raises(exceptions.KeyGenerationError):
        KeyPair.generate(key_size=100)  # type: ignore
