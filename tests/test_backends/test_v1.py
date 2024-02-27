import io
from unittest.mock import MagicMock

import pytest

from kek import EncryptionBackend, PublicKey, exceptions
from kek.backends import v1


def _validate_v1_encrypted_data(encrypted: bytes, original: bytes):
    assert len(encrypted) > len(original)
    assert len(encrypted) <= len(original) + v1.SYMMETRIC_BLOCK_LENGTH
    assert len(encrypted) % v1.SYMMETRIC_BLOCK_LENGTH == 0


def test_encryptor_get_header(
    v1_encryptor: EncryptionBackend,
    public_key: PublicKey,
):
    header = v1_encryptor.get_header()
    assert header[0] == 1
    assert header[1:] == public_key.key_id


def test_encryptor_get_metadata(
    v1_encryptor: EncryptionBackend,
    public_key: PublicKey,
):
    header = v1_encryptor.get_header()
    metadata = v1_encryptor.get_metadata()
    assert metadata.startswith(header)
    assert len(metadata) - len(header) == public_key.key_size / 8


def test_encryptor_encrypt_message(
    v1_encryptor: EncryptionBackend,
    sample_message: bytes,
):
    encrypted_message = v1_encryptor.encrypt(sample_message)
    _validate_v1_encrypted_data(encrypted_message, sample_message)


def test_encryptor_encrypt_stream(
    v1_encryptor: EncryptionBackend,
    sample_message: bytes,
    sample_message_buffer: io.BufferedIOBase,
):
    stream_encryption_iterator = v1_encryptor.encrypt_stream(sample_message_buffer)
    encrypted_message = b"".join(stream_encryption_iterator)
    _validate_v1_encrypted_data(encrypted_message, sample_message)


def test_encryptor_encrypt_stream_custom_chunk_length(
    v1_encryptor: EncryptionBackend,
    sample_message: bytes,
    sample_message_buffer: io.BufferedIOBase,
):
    stream_encryption_iterator = v1_encryptor.encrypt_stream(
        sample_message_buffer,
        chunk_length=64,
    )
    encrypted_message = b"".join(stream_encryption_iterator)
    _validate_v1_encrypted_data(encrypted_message, sample_message)


def test_encryptor_encrypt_stream_invalid_chunk_length(
    v1_encryptor: EncryptionBackend,
    sample_message_buffer: io.BufferedIOBase,
):
    with pytest.raises(exceptions.EncryptionError):
        v1_encryptor.encrypt_stream(sample_message_buffer, chunk_length=1)


def test_encryptor_encrypt_stream_exception(v1_encryptor: EncryptionBackend):
    buffer_mock = MagicMock(io.BufferedIOBase)
    buffer_mock.read.side_effect = Exception()
    with pytest.raises(exceptions.EncryptionError):
        stream_encryption_iterator = v1_encryptor.encrypt_stream(buffer_mock)
        next(stream_encryption_iterator)
