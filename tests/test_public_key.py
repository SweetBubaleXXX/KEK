import io

import pytest

from kek import PublicKey

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
    message_for_signing: bytes,
    public_key: PublicKey,
):
    assert public_key.verify(message_signature, message_for_signing)


def test_verify_invalid_message(
    message_signature: bytes,
    public_key: PublicKey,
):
    assert not public_key.verify(message_signature, b"invalid message")


def test_verify_invalid_signature(
    message_for_signing: bytes,
    public_key: PublicKey,
):
    assert not public_key.verify(b"invalid signature", message_for_signing)


def test_verify_stream(
    message_signature: bytes,
    message_for_signing: bytes,
    public_key: PublicKey,
):
    stream = io.BytesIO(message_for_signing)
    assert public_key.verify_stream(message_signature, stream)
    assert stream.tell() == len(message_for_signing)


def test_verify_iterable(
    message_signature: bytes,
    message_for_signing: bytes,
    public_key: PublicKey,
):
    iterator = map(int.to_bytes, message_for_signing)
    assert public_key.verify_iterable(message_signature, iterator)
    with pytest.raises(StopIteration):
        next(iterator)


@pytest.mark.asyncio
async def test_verify_async_iterable(
    message_signature: bytes,
    message_for_signing: bytes,
    public_key: PublicKey,
):
    iterator = async_iterator(message_for_signing)
    assert await public_key.verify_async_iterable(message_signature, iterator)
    with pytest.raises(StopAsyncIteration):
        await anext(iterator)
