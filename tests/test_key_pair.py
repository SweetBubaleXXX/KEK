import io

import pytest

from kek import KeyPair, exceptions
from kek.constants import SUPPORTED_KEY_SIZES

from .helpers import async_iterator


def test_load_key(serialized_private_key: bytes, key_size: int):
    loaded_key_pair = KeyPair.load(serialized_private_key)
    assert isinstance(loaded_key_pair, KeyPair)
    assert loaded_key_pair.key_size == key_size


def test_load_unencrypted_key_with_password(
    serialized_private_key: bytes,
):
    with pytest.raises(exceptions.KeyLoadingError):
        KeyPair.load(serialized_private_key, password=b"password")


def test_load_encrypted_key(
    encrypted_private_key: bytes,
    key_encryption_password: bytes,
):
    KeyPair.load(encrypted_private_key, password=key_encryption_password)


def test_load_encrypted_key_without_password(encrypted_private_key: bytes):
    with pytest.raises(exceptions.KeyLoadingError):
        KeyPair.load(encrypted_private_key)


@pytest.mark.parametrize("size", SUPPORTED_KEY_SIZES)
def test_generate_key_pair(size):
    generated_key_pair = KeyPair.generate(size)
    assert isinstance(generated_key_pair, KeyPair)


def test_generate_key_pair_invalid_key_size():
    with pytest.raises(exceptions.KeyGenerationError):
        KeyPair.generate(key_size=100)  # type: ignore


def test_key_id(key_pair: KeyPair, key_id: bytes):
    assert key_pair.key_id == key_id


def test_public_key_id(key_pair: KeyPair):
    assert key_pair.public_key.key_id == key_pair.key_id


def test_serialize_key_without_password(
    key_pair: KeyPair,
    serialized_private_key: bytes,
):
    result = key_pair.serialize()
    assert result == serialized_private_key


def test_serialize_key_with_password(key_pair: KeyPair):
    result = key_pair.serialize(password=b"password")
    first_line = result.splitlines()[0]
    assert b"ENCRYPTED" in first_line


def test_serialize_key_error(key_pair: KeyPair):
    with pytest.raises(exceptions.KeySerializationError):
        key_pair.serialize(123)  # type: ignore


def test_sign_message(key_pair: KeyPair, sample_message: bytes):
    key_pair.sign(sample_message)


def test_sign_stream(
    key_pair: KeyPair,
    sample_message: bytes,
    sample_message_buffer: io.BufferedIOBase,
):
    key_pair.sign_stream(sample_message_buffer)
    assert sample_message_buffer.tell() == len(sample_message)


def test_sign_iterable(key_pair: KeyPair):
    iterator = (b"chunk" for _ in range(3))
    key_pair.sign_iterable(iterator)
    with pytest.raises(StopIteration):
        next(iterator)


@pytest.mark.asyncio
async def test_sign_async_iterable(key_pair: KeyPair):
    iterator = async_iterator(b"message")
    await key_pair.sign_async_iterable(iterator)
    with pytest.raises(StopAsyncIteration):
        await anext(iterator)


def test_sign_and_verify(key_pair: KeyPair, sample_message: bytes):
    signature = key_pair.sign(sample_message)
    assert key_pair.public_key.verify(signature, message=sample_message)
