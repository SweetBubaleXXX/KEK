import io
from unittest.mock import MagicMock

import pytest

from gnukek import constants, exceptions
from gnukek.backends import v1
from tests.constants import SAMPLE_MESSAGE


def _validate_v1_encrypted_data(encrypted: bytes, original: bytes):
    assert len(encrypted) > len(original)
    assert len(encrypted) <= len(original) + v1.SYMMETRIC_BLOCK_LENGTH
    assert len(encrypted) % v1.SYMMETRIC_BLOCK_LENGTH == 0


def test_encryptor_version():
    assert v1.Encryptor.version == 1


def test_encryptor_get_header(v1_encryptor, public_key):
    header = v1_encryptor.get_header()
    assert header[0] == 1
    assert header[1:] == public_key.key_id


def test_encryptor_get_metadata(v1_encryptor, public_key):
    header = v1_encryptor.get_header()
    metadata = v1_encryptor.get_metadata()
    assert metadata.startswith(header)
    assert len(metadata) - len(header) == public_key.key_size / 8


def test_encryptor_encrypt_message(v1_encryptor, sample_message):
    encrypted_message = v1_encryptor.encrypt(sample_message)
    _validate_v1_encrypted_data(encrypted_message, sample_message)


def test_encryptor_encrypt_stream(v1_encryptor, sample_message, sample_message_buffer):
    stream_encryption_iterator = v1_encryptor.encrypt_stream(sample_message_buffer)
    encrypted_message = b"".join(stream_encryption_iterator)
    _validate_v1_encrypted_data(encrypted_message, sample_message)


def test_encryptor_encrypt_stream_custom_chunk_length(
    v1_encryptor,
    sample_message,
    sample_message_buffer,
):
    stream_encryption_iterator = v1_encryptor.encrypt_stream(
        sample_message_buffer,
        chunk_length=64,
    )
    encrypted_message = b"".join(stream_encryption_iterator)
    _validate_v1_encrypted_data(encrypted_message, sample_message)


def test_encryptor_encrypt_stream_invalid_chunk_length(
    v1_encryptor, sample_message_buffer
):
    with pytest.raises(exceptions.EncryptionError):
        v1_encryptor.encrypt_stream(sample_message_buffer, chunk_length=1)


def test_encryptor_encrypt_stream_exception(v1_encryptor):
    buffer_mock = MagicMock(io.BufferedIOBase)
    buffer_mock.read.side_effect = Exception()
    with pytest.raises(exceptions.EncryptionError):
        stream_encryption_iterator = v1_encryptor.encrypt_stream(buffer_mock)
        next(stream_encryption_iterator)


def test_decryptor_version():
    assert v1.Decryptor.version == 1


def test_decryptor_decrypt_message(v1_decryptor_factory, encrypted_message):
    decryptor = v1_decryptor_factory(encrypted_message)
    decrypted_message = decryptor.decrypt()
    assert decrypted_message == SAMPLE_MESSAGE


def test_decryptor_decrypt_invalid_length_data(v1_decryptor_factory, encrypted_message):
    decryptor = v1_decryptor_factory(encrypted_message[:-1])
    with pytest.raises(exceptions.DecryptionError):
        decryptor.decrypt()


def test_decryptor_decrypt_empty_data(v1_decryptor_factory):
    decryptor = v1_decryptor_factory(b"")
    with pytest.raises(exceptions.DecryptionError):
        decryptor.decrypt()


def test_stream_decryptor_decrypt_message(
    v1_stream_decryptor_factory, encrypted_message
):
    message_without_header = encrypted_message[constants.KEY_ID_SLICE.stop :]
    decryptor = v1_stream_decryptor_factory(io.BytesIO(message_without_header))

    decrypted_message = b"".join(decryptor.decrypt_stream())
    assert decrypted_message == SAMPLE_MESSAGE


def test_stream_decryptor_decrypt_custom_chunk_length(
    v1_stream_decryptor_factory, encrypted_message
):
    message_without_header = encrypted_message[constants.KEY_ID_SLICE.stop :]
    decryptor = v1_stream_decryptor_factory(io.BytesIO(message_without_header))

    decrypted_message = b"".join(
        decryptor.decrypt_stream(chunk_length=v1.SYMMETRIC_BLOCK_LENGTH)
    )
    assert decrypted_message == SAMPLE_MESSAGE


def test_stream_decryptor_decrypt_invalid_length_stream(
    v1_stream_decryptor_factory, encrypted_message
):
    broken_message = encrypted_message[constants.KEY_ID_SLICE.stop : -1]
    decryptor = v1_stream_decryptor_factory(io.BytesIO(broken_message))
    with pytest.raises(exceptions.DecryptionError):
        next(decryptor.decrypt_stream())


def test_stream_decryptor_decrypt_empty_stream(v1_stream_decryptor_factory):
    decryptor = v1_stream_decryptor_factory(io.BytesIO(b""))
    with pytest.raises(exceptions.DecryptionError):
        next(decryptor.decrypt_stream())
