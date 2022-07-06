class BaseSymmetricKey:
    algorithm: str

    def __init__(self) -> None:
        pass

    @staticmethod
    def generate() -> object:
        pass

    def encrypt(self) -> bytes:
        pass

    def decrypt(self) -> bytes:
        pass


class BasePrivateKey:
    algorithm: str

    def __init__(self) -> None:
        pass

    @property
    def public_key(self) -> object:
        pass

    @staticmethod
    def generate() -> object:
        pass

    @staticmethod
    def load() -> object:
        pass

    def serialize(self) -> bytes:
        pass

    def encrypt(self) -> bytes:
        pass

    def decrypt(self) -> bytes:
        pass

    def sign(self) -> bytes:
        pass

    def verify(self) -> bool:
        pass


class BasePublicKey:
    algorithm: str

    def __init__(self) -> None:
        pass

    @staticmethod
    def load() -> object:
        pass

    def serialize(self) -> bytes:
        pass

    def encrypt(self) -> bytes:
        pass

    def verify(self) -> bool:
        pass
