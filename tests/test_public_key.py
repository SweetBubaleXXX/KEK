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


def test_v1_encryptor_encrypt_message(
    v1_encryptor: EncryptionBackend,
    sample_message: bytes,
):
    encrypted_message = v1_encryptor.encrypt(sample_message)
    _validate_v1_encrypted_data(encrypted_message, sample_message)


def test_v1_encryptor_encrypt_stream(
    v1_encryptor: EncryptionBackend,
    sample_message: bytes,
    sample_message_buffer: io.BufferedIOBase,
):
    stream_encryption_generator = v1_encryptor.encrypt_stream(sample_message_buffer)
    encrypted_message = b"".join(stream_encryption_generator)
    _validate_v1_encrypted_data(encrypted_message, sample_message)


def test_v1_encryptor_encrypt_stream_custom_chunk_size(
    v1_encryptor: EncryptionBackend,
    sample_message: bytes,
    sample_message_buffer: io.BufferedIOBase,
):
    stream_encryption_generator = v1_encryptor.encrypt_stream(
        sample_message_buffer,
        chunk_length=64,
    )
    encrypted_message = b"".join(stream_encryption_generator)
    _validate_v1_encrypted_data(encrypted_message, sample_message)
