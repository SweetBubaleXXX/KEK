import pytest

from kek import PublicKey
from kek.constants import LATEST_KEK_VERSION

from .helpers import async_iterator


def test_load_key(serialized_public_key, key_size):
    key = PublicKey.load(serialized_public_key)
    assert isinstance(key, PublicKey)
    assert key.key_size == key_size


def test_serialize_key(public_key, serialized_public_key):
    result = public_key.serialize()
    assert result == serialized_public_key


def test_verify_message(message_signature, sample_message, public_key):
    assert public_key.verify(message_signature, message=sample_message)


def test_verify_invalid_message(message_signature, public_key):
    assert not public_key.verify(message_signature, message=b"invalid message")


def test_verify_invalid_signature(sample_message, public_key):
    assert not public_key.verify(b"invalid signature", message=sample_message)


def test_verify_stream(
    message_signature,
    sample_message,
    sample_message_buffer,
    public_key,
):
    assert public_key.verify_stream(message_signature, buffer=sample_message_buffer)
    assert sample_message_buffer.tell() == len(sample_message)


def test_verify_iterable(message_signature, sample_message, public_key):
    iterator = map(lambda char: char.to_bytes(1, "big"), sample_message)
    assert public_key.verify_iterable(message_signature, iterable=iterator)
    with pytest.raises(StopIteration):
        next(iterator)


@pytest.mark.asyncio
async def test_verify_async_iterable(message_signature, sample_message, public_key):
    iterator = async_iterator(sample_message)
    assert await public_key.verify_async_iterable(message_signature, iterable=iterator)
    with pytest.raises(StopAsyncIteration):
        await anext(iterator)


def test_get_default_encryptor(public_key):
    encryptor = public_key.get_encryptor()
    assert encryptor.version == LATEST_KEK_VERSION


@pytest.mark.parametrize("version", (-1, 0, LATEST_KEK_VERSION + 1))
def test_get_encryptor_invalid_version(version, public_key):
    with pytest.raises(ValueError):
        public_key.get_encryptor(version=version)
