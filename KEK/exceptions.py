"""Module with exception classes."""

from functools import wraps
from typing import Callable, Type

BASE_ERROR_MESSAGE = "Exception occurred while {}."


class KeyGenerationError(Exception):
    def __init__(self, message: str = BASE_ERROR_MESSAGE.format(
            "generating key")) -> None:
        super().__init__(message)


class KeyLoadingError(Exception):
    def __init__(self, message: str = BASE_ERROR_MESSAGE.format(
            "loading key")) -> None:
        super().__init__(message)


class KeySerializationError(Exception):
    def __init__(self, message: str = BASE_ERROR_MESSAGE.format(
            "serializing key")) -> None:
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


class SigningError(Exception):
    def __init__(self, message: str = BASE_ERROR_MESSAGE.format(
            "signing data")) -> None:
        super().__init__(message)


class VerificationError(Exception):
    def __init__(self, message: str = BASE_ERROR_MESSAGE.format(
            "verifying data")) -> None:
        super().__init__(message)


def raises(exception: Type[Exception]) -> Callable:
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except exception:
                raise
            except Exception as e:
                raise exception(e) from e
        return wrapper
    return decorator
