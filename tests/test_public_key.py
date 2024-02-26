import io

import pytest

from kek import EncryptionBackend, PublicKey
from kek.backends import v1

from .helpers import async_iterator


def _validate_v1_encrypted_data(encrypted: bytes, original: bytes):
    assert len(encrypted) > len(original)
    assert len(encrypted) <= len(original) + v1.SYMMETRIC_BLOCK_LENGTH
    assert len(encrypted) % v1.SYMMETRIC_BLOCK_LENGTH == 0


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
    assert public_key.verify(message_signature, message=message_for_signing)


def test_verify_invalid_message(
    message_signature: bytes,
    public_key: PublicKey,
):
    assert not public_key.verify(message_signature, message=b"invalid message")


def test_verify_invalid_signature(
    message_for_signing: bytes,
    public_key: PublicKey,
):
    assert not public_key.verify(b"invalid signature", message=message_for_signing)


def test_verify_stream(
    message_signature: bytes,
    message_for_signing: bytes,
    public_key: PublicKey,
):
    stream = io.BytesIO(message_for_signing)
    assert public_key.verify_stream(message_signature, buffer=stream)
    assert stream.tell() == len(message_for_signing)


def test_verify_iterable(
    message_signature: bytes,
    message_for_signing: bytes,
    public_key: PublicKey,
):
    iterator = map(int.to_bytes, message_for_signing)
    assert public_key.verify_iterable(message_signature, iterable=iterator)
    with pytest.raises(StopIteration):
        next(iterator)


@pytest.mark.asyncio
async def test_verify_async_iterable(
    message_signature: bytes,
    message_for_signing: bytes,
    public_key: PublicKey,
):
    iterator = async_iterator(message_for_signing)
    assert await public_key.verify_async_iterable(message_signature, iterable=iterator)
    with pytest.raises(StopAsyncIteration):
        await anext(iterator)


def test_v1_encryptor_get_header(
    v1_encryptor: EncryptionBackend,
    public_key: PublicKey,
):
    header = v1_encryptor.get_header()
    assert header[0] == 1
    assert header[1:] == public_key.key_id


def test_v1_encryptor_get_metadata(
    v1_encryptor: EncryptionBackend,
    public_key: PublicKey,
):
    header = v1_encryptor.get_header()
    metadata = v1_encryptor.get_metadata()
    assert metadata.startswith(header)
    assert len(metadata) - len(header) == public_key.key_size / 8


def test_v1_encryptor_encrypt_message(v1_encryptor: EncryptionBackend):
    message = b"message for encryption"
    encrypted_message = v1_encryptor.encrypt(message)
    _validate_v1_encrypted_data(encrypted_message, message)


def test_v1_encryptor_encrypt_stream(v1_encryptor: EncryptionBackend):
    message = b"message for encryption"
    stream = io.BytesIO(message)
    encrypted_message = b"".join(v1_encryptor.encrypt_stream(stream))
    _validate_v1_encrypted_data(encrypted_message, message)
