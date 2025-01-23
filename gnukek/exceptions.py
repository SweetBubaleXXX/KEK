from functools import wraps
from typing import Awaitable, Callable, ParamSpec, Type, TypeVar

T = TypeVar("T")
P = ParamSpec("P")


class KekException(Exception):
    """Generic KEK exception."""

    DEFAULT_MESSAGE = "An error occurred"

    def __init__(self, message: str | None = None, *args: object) -> None:
        super().__init__(message or self.DEFAULT_MESSAGE, *args)


class KeyGenerationError(KekException):
    DEFAULT_MESSAGE = "Failed to generate key"


class KeyLoadingError(KekException):
    DEFAULT_MESSAGE = "Failed to load key"


class KeySerializationError(KekException):
    DEFAULT_MESSAGE = "Failed to serialize key"


class SigningError(KekException):
    DEFAULT_MESSAGE = "Failed to create signature"


class VerificationError(KekException):
    DEFAULT_MESSAGE = "Error occurred while verifying signature"


class EncryptionError(KekException):
    DEFAULT_MESSAGE = "Encryption failed"


class DecryptionError(KekException):
    DEFAULT_MESSAGE = "Decryption failed"


def raises(
    exception_type: Type[Exception],
    *exc_args,
    **exc_kwargs,
) -> Callable[[Callable[P, T]], Callable[P, T]]:
    """Catch exceptions and re-raise an exception of the specified type with kwargs."""

    def decorator(func: Callable[P, T]) -> Callable[P, T]:
        @wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            try:
                return func(*args, **kwargs)
            except KekException as exc:
                if isinstance(exc, exception_type):
                    raise
                raise exception_type(*exc_args, **exc_kwargs) from exc
            except StopIteration:
                raise
            except Exception as exc:
                raise exception_type(*exc_args, **exc_kwargs) from exc

        return wrapper

    return decorator


def raises_async(
    exception_type: Type[Exception],
    *exc_args,
    **exc_kwargs,
) -> Callable[[Callable[P, Awaitable[T]]], Callable[P, Awaitable[T]]]:
    """Same as `raises()` but for async functions."""

    def decorator(func: Callable[P, Awaitable[T]]) -> Callable[P, Awaitable[T]]:
        @wraps(func)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            try:
                return await func(*args, **kwargs)
            except KekException as exc:
                if isinstance(exc, exception_type):
                    raise
                raise exception_type(*exc_args, **exc_kwargs) from exc
            except StopAsyncIteration:
                raise
            except Exception as exc:
                raise exception_type(*exc_args, **exc_kwargs) from exc

        return wrapper

    return decorator
