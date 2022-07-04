class BaseSymmetricKey:
    algorithm: str

    def __init__(self) -> None:
        pass

    @staticmethod
    def generate() -> object:
        pass

    def encrypt() -> bytes:
        pass

    def decrypt() -> bytes:
        pass


class BasePrivateKey:
    algorithm: str

    def __init__(self) -> None:
        pass

    @staticmethod
    def generate() -> object:
        pass

    def serialize() -> bytes:
        pass

    def encrypt() -> bytes:
        pass

    def decrypt() -> bytes:
        pass

    def verify() -> bool:
        pass

    def sign() -> bytes:
        pass

    def public_key() -> object:
        pass


class BasePublicKey:
    algorithm: str

    def __init__(self) -> None:
        pass

    def serialize() -> bytes:
        pass

    def encrypt() -> bytes:
        pass

    def verify() -> bool:
        pass
