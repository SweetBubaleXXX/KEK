import pytest

from gnukek import exceptions
from gnukek.constants import SerializedKeyType
from gnukek.utils import (
    PreprocessedEncryptedStream,
    extract_key_id,
    get_key_type,
    preprocess_encrypted_stream,
)
from tests.constants import (
    ENCRYPTED_PRIVATE_KEY,
    SERIALIZED_PRIVATE_KEY,
    SERIALIZED_PUBLIC_KEY,
)


@pytest.fixture()
def empty_file_path(tmp_path):
    tmp_file_path = tmp_path / "empty_file.kek"
    tmp_file_path.touch()
    return tmp_file_path


def test_preprocess_encrypted_stream(encrypted_stream, key_id):
    preprocessed_stream = preprocess_encrypted_stream(encrypted_stream)

    assert isinstance(preprocessed_stream, PreprocessedEncryptedStream)
    assert preprocessed_stream.algorithm_version == 1
    assert preprocessed_stream.key_id == key_id


def test_preprocess_empty_stream(empty_file_path):
    with open(empty_file_path, "rb", buffering=0) as f:
        with pytest.raises(exceptions.DecryptionError):
            preprocess_encrypted_stream(f)


def test_extract_key_id(encrypted_message, key_id):
    extracted_key_id = extract_key_id(encrypted_message)
    assert extracted_key_id == key_id


@pytest.mark.parametrize(
    ("serialized_key", "expected_type"),
    [
        (SERIALIZED_PUBLIC_KEY, SerializedKeyType.PUBLIC_KEY),
        (SERIALIZED_PRIVATE_KEY, SerializedKeyType.PRIVATE_KEY),
        (ENCRYPTED_PRIVATE_KEY, SerializedKeyType.ENCRYPTED_PRIVATE_KEY),
        (b"unknown_key", SerializedKeyType.UNKNOWN),
    ],
)
def test_get_key_type(serialized_key, expected_type):
    key_type = get_key_type(serialized_key)
    assert key_type == expected_type
