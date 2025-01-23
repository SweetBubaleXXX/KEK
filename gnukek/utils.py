from io import BufferedReader, RawIOBase

from gnukek import constants, exceptions
from gnukek.constants import KEY_ID_LENGTH
from gnukek.exceptions import raises


class PreprocessedEncryptedStream(BufferedReader):
    def __init__(
        self,
        original_stream: RawIOBase,
        *,
        algorithm_version: int,
        key_id: bytes,
    ) -> None:
        super().__init__(original_stream)
        self._original_stream = original_stream
        self._algorithm_version = algorithm_version
        self._key_id = key_id

    @property
    def algorithm_version(self) -> int:
        return self._algorithm_version

    @property
    def key_id(self) -> bytes:
        return self._key_id


@raises(exceptions.DecryptionError)
def preprocess_encrypted_stream(raw_stream: RawIOBase) -> PreprocessedEncryptedStream:
    algorithm_version = raw_stream.read(1)[0]
    key_id = raw_stream.read(KEY_ID_LENGTH)

    if len(key_id) < KEY_ID_LENGTH:
        raise exceptions.DecryptionError("Failed to extract key id")

    return PreprocessedEncryptedStream(
        raw_stream,
        algorithm_version=algorithm_version,
        key_id=key_id,
    )


def extract_key_id(encrypted_message: bytes) -> bytes:
    return encrypted_message[constants.KEY_ID_SLICE]


def get_key_type(serialized_key: bytes) -> constants.SerializedKeyType:
    if serialized_key.startswith(b"-----BEGIN PUBLIC KEY-----"):
        return constants.SerializedKeyType.PUBLIC_KEY
    elif serialized_key.startswith(b"-----BEGIN PRIVATE KEY-----"):
        return constants.SerializedKeyType.PRIVATE_KEY
    elif serialized_key.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----"):
        return constants.SerializedKeyType.ENCRYPTED_PRIVATE_KEY
    return constants.SerializedKeyType.UNKNOWN
