from typing import Callable, Type

BASE_ERROR_MESSAGE = "Exception occurred while {}."


class KeyGenerationError(Exception):
    def __init__(self, message: str = BASE_ERROR_MESSAGE.format(
            "generating key")) -> None:
        super().__init__(message)


class EncryptionError(Exception):
    def __init__(self,
                 message: str = BASE_ERROR_MESSAGE.format(
            "encrypting data")) -> None:
        super().__init__(message)


class DecryptionError(Exception):
    def __init__(self, message: str = BASE_ERROR_MESSAGE.format(
            "decrypting data")) -> None:
        super().__init__(message)


def raises(exception: Type[Exception]) -> Callable:
    def decorator(func: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except exception:
                raise
            except Exception as e:
                raise exception(e) from e
        return wrapper
    return decorator
