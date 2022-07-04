from typing import Iterable


class BaseSymmetricKey:
    algorithm: str
    block_size: int

    def __init__(self) -> None:
        pass

    @staticmethod
    def generate() -> object:
        pass

    def encrypt() -> bytes:
        pass

    def decrypt() -> bytes:
        pass
