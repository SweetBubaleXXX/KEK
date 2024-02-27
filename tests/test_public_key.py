import io

import pytest

from kek import PublicKey
from kek.constants import LATEST_KEK_VERSION

from .helpers import async_iterator


def test_load_key(serialized_public_key: bytes, key_size: int):
    key = PublicKey.load(serialized_public_key)
    assert isinstance(key, PublicKey)
    assert key.key_size == key_size


def test_serialize_key(public_key: PublicKey, serialized_public_key: bytes):
    result = public_key.serialize()
    assert result == serialized_public_key


def test_verify_message(
    message_signature: bytes,
    sample_message: bytes,
    public_key: PublicKey,
):
    assert public_key.verify(message_signature, message=sample_message)


def test_verify_invalid_message(
    message_signature: bytes,
    public_key: PublicKey,
):
    assert not public_key.verify(message_signature, message=b"invalid message")


def test_verify_invalid_signature(
    sample_message: bytes,
    public_key: PublicKey,
):
    assert not public_key.verify(b"invalid signature", message=sample_message)


def test_verify_stream(
    message_signature: bytes,
    sample_message: bytes,
    sample_message_buffer: io.BufferedIOBase,
    public_key: PublicKey,
):
    assert public_key.verify_stream(message_signature, buffer=sample_message_buffer)
    assert sample_message_buffer.tell() == len(sample_message)


def test_verify_iterable(
    message_signature: bytes,
    sample_message: bytes,
    public_key: PublicKey,
):
    iterator = map(int.to_bytes, sample_message)
    assert public_key.verify_iterable(message_signature, iterable=iterator)
    with pytest.raises(StopIteration):
        next(iterator)


@pytest.mark.asyncio
async def test_verify_async_iterable(
    message_signature: bytes,
    sample_message: bytes,
    public_key: PublicKey,
):
    iterator = async_iterator(sample_message)
    assert await public_key.verify_async_iterable(message_signature, iterable=iterator)
    with pytest.raises(StopAsyncIteration):
        await anext(iterator)


def test_get_default_encryptor(public_key: PublicKey):
    encryptor = public_key.get_encryptor()
    assert encryptor.version == LATEST_KEK_VERSION
