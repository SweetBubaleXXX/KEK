import pytest

from kek import KeyPair, exceptions


def test_load_key(serialized_private_key: bytes, key_size: int):
    loaded_key_pair = KeyPair.load(serialized_private_key)
    assert isinstance(loaded_key_pair, KeyPair)
    assert loaded_key_pair.key_size == key_size


def test_load_unencrypted_key_with_password(
    serialized_private_key: bytes,
    key_encryption_password: bytes,
):
    with pytest.raises(exceptions.KeyLoadingError):
        KeyPair.load(serialized_private_key, key_encryption_password)


def test_load_encrypted_key(
    encrypted_private_key: bytes,
    key_encryption_password: bytes,
):
    KeyPair.load(encrypted_private_key, key_encryption_password)


def test_load_encrypted_key_without_password(encrypted_private_key: bytes):
    with pytest.raises(exceptions.KeyLoadingError):
        KeyPair.load(encrypted_private_key)


def test_generate_key_pair():
    generated_key_pair = KeyPair.generate()
    assert isinstance(generated_key_pair, KeyPair)


def test_generate_key_pair_invalid_key_size():
    with pytest.raises(exceptions.KeyGenerationError):
        KeyPair.generate(key_size=100)  # type: ignore
