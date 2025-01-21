import pytest

from kek import exceptions
from kek.utils import PreprocessedEncryptedStream, preprocess_encrypted_stream


@pytest.fixture()
def empty_file_path(tmp_path):
    tmp_file_path = tmp_path / "empty_file.kek"
    tmp_file_path.touch()
    return tmp_file_path


def test_preprocess_encrypted_stream(encrypted_file_path, key_id):
    with open(encrypted_file_path, "rb", buffering=0) as f:
        preprocessed_stream = preprocess_encrypted_stream(f)

    assert isinstance(preprocessed_stream, PreprocessedEncryptedStream)
    assert preprocessed_stream.algorithm_version == 1
    assert preprocessed_stream.key_id == key_id


def test_preprocess_empty_stream(empty_file_path):
    with open(empty_file_path, "rb", buffering=0) as f:
        with pytest.raises(exceptions.DecryptionError):
            preprocess_encrypted_stream(f)
