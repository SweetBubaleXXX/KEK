from abc import ABCMeta

from ..constants import KekAlgorithmVersion


class DecryptionBackend(metaclass=ABCMeta):
    version: KekAlgorithmVersion

    def __init__(self, key_id: bytes) -> None:
        self._key_id = key_id
