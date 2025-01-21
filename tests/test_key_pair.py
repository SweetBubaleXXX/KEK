import io

import pytest

from kek import KeyPair, exceptions
from kek.constants import KEY_ID_SLICE, LATEST_KEK_VERSION, SUPPORTED_KEY_SIZES
from kek.utils import preprocess_encrypted_stream

from .helpers import async_iterator


def test_load_key(serialized_private_key, key_size):
    loaded_key_pair = KeyPair.load(serialized_private_key)
    assert isinstance(loaded_key_pair, KeyPair)
    assert loaded_key_pair.key_size == key_size


def test_load_unencrypted_key_with_password(serialized_private_key):
    with pytest.raises(exceptions.KeyLoadingError):
        KeyPair.load(serialized_private_key, password=b"password")


def test_load_encrypted_key(encrypted_private_key, key_encryption_password):
    KeyPair.load(encrypted_private_key, password=key_encryption_password)


def test_load_encrypted_key_without_password(encrypted_private_key):
    with pytest.raises(exceptions.KeyLoadingError):
        KeyPair.load(encrypted_private_key)


@pytest.mark.parametrize("size", SUPPORTED_KEY_SIZES)
def test_generate_key_pair(size):
    generated_key_pair = KeyPair.generate(size)
    assert isinstance(generated_key_pair, KeyPair)


def test_generate_key_pair_invalid_key_size():
    with pytest.raises(exceptions.KeyGenerationError):
        KeyPair.generate(key_size=100)  # type: ignore


def test_key_id(key_pair, key_id):
    assert key_pair.key_id == key_id


def test_public_key_id(key_pair):
    assert key_pair.public_key.key_id == key_pair.key_id


def test_serialize_key_without_password(key_pair, serialized_private_key):
    result = key_pair.serialize()
    assert result == serialized_private_key


def test_serialize_key_with_password(key_pair):
    result = key_pair.serialize(password=b"password")
    first_line = result.splitlines()[0]
    assert b"ENCRYPTED" in first_line


def test_serialize_key_error(key_pair):
    with pytest.raises(exceptions.KeySerializationError):
        key_pair.serialize(123)  # type: ignore


def test_sign_message(key_pair, sample_message):
    key_pair.sign(sample_message)


def test_sign_stream(key_pair, sample_message, sample_message_buffer):
    key_pair.sign_stream(sample_message_buffer)
    assert sample_message_buffer.tell() == len(sample_message)


def test_sign_iterable(key_pair):
    iterator = (b"chunk" for _ in range(3))
    key_pair.sign_iterable(iterator)
    with pytest.raises(StopIteration):
        next(iterator)


@pytest.mark.asyncio
async def test_sign_async_iterable(key_pair):
    iterator = async_iterator(b"message")
    await key_pair.sign_async_iterable(iterator)
    with pytest.raises(StopAsyncIteration):
        await anext(iterator)


def test_sign_and_verify(key_pair, sample_message):
    signature = key_pair.sign(sample_message)
    assert key_pair.public_key.verify(signature, message=sample_message)


def test_decrypt_message(key_pair, encrypted_message, sample_message):
    decrypted_message = key_pair.decrypt(encrypted_message)
    assert decrypted_message == sample_message


def test_decrypt_different_key_id(key_pair, encrypted_message):
    message_with_different_id = bytearray(encrypted_message)
    message_with_different_id[KEY_ID_SLICE] = b"12345678"
    with pytest.raises(exceptions.DecryptionError) as exc_info:
        key_pair.decrypt(message_with_different_id)
        assert "different key" in exc_info.value.args[0]


def test_decrypt_unsupported_version(key_pair, encrypted_message):
    unsupported_version = LATEST_KEK_VERSION + 1
    message_with_unsupported_version = (
        unsupported_version.to_bytes() + encrypted_message[1:]
    )
    with pytest.raises(exceptions.DecryptionError) as exc_info:
        key_pair.decrypt(message_with_unsupported_version)
        assert "unsupported version" in exc_info.value.args[0]


def test_decrypt_stream(key_pair, encrypted_stream, sample_message):
    decryption_iterator = key_pair.decrypt_stream(encrypted_stream)
    decrypted_message = b"".join(decryption_iterator)
    assert decrypted_message == sample_message


def test_decrypt_preprocessed_stream(key_pair, encrypted_file_path, sample_message):
    with open(encrypted_file_path, "rb", buffering=0) as f:
        preprocessed_stream = preprocess_encrypted_stream(f)
        decryption_iterator = key_pair.decrypt_stream(preprocessed_stream)
        decrypted_message = b"".join(decryption_iterator)
    assert decrypted_message == sample_message


def test_decrypt_stream_different_key_id(key_pair, encrypted_message):
    message_with_different_id = bytearray(encrypted_message)
    message_with_different_id[KEY_ID_SLICE] = b"12345678"
    buffer = io.BytesIO(message_with_different_id)
    with pytest.raises(exceptions.DecryptionError) as exc_info:
        key_pair.decrypt_stream(buffer)
        assert "different key" in exc_info.value.args[0]


def test_decrypt_stream_unsupported_version(key_pair, encrypted_message):
    unsupported_version = LATEST_KEK_VERSION + 1
    message_with_unsupported_version = (
        unsupported_version.to_bytes() + encrypted_message[1:]
    )
    buffer = io.BytesIO(message_with_unsupported_version)
    with pytest.raises(exceptions.DecryptionError) as exc_info:
        key_pair.decrypt_stream(buffer)
        assert "unsupported version" in exc_info.value.args[0]
