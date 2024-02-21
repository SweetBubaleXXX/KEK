from functools import wraps
from typing import Awaitable, Callable, ParamSpec, Type, TypeVar

T = TypeVar("T")
P = ParamSpec("P")


class KekException(Exception):
    pass


class KeyGenerationError(KekException):
    def __init__(self, message: str = "Failed to generate key", *args: object) -> None:
        super().__init__(message, *args)


class KeyLoadingError(KekException):
    def __init__(self, message: str = "Failed to load key", *args: object) -> None:
        super().__init__(message, *args)


def raises(
    exception_type: Type[Exception],
    *exc_args,
    **exc_kwargs,
) -> Callable[[Callable[P, T]], Callable[P, T]]:
    def decorator(func: Callable[P, T]) -> Callable[P, T]:
        @wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            try:
                return func(*args, **kwargs)
            except KekException as exc:
                if isinstance(exc, exception_type):
                    raise
                raise exception_type(*exc_args, **exc_kwargs) from exc
            except Exception as exc:
                raise exception_type(*exc_args, **exc_kwargs) from exc

        return wrapper

    return decorator


def async_raises(
    exception_type: Type[Exception],
    *exc_args,
    **exc_kwargs,
) -> Callable[[Callable[P, Awaitable[T]]], Callable[P, Awaitable[T]]]:
    def decorator(func: Callable[P, Awaitable[T]]) -> Callable[P, Awaitable[T]]:
        @wraps(func)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            try:
                return await func(*args, **kwargs)
            except KekException as exc:
                if isinstance(exc, exception_type):
                    raise
                raise exception_type(*exc_args, **exc_kwargs) from exc
            except Exception as exc:
                raise exception_type(*exc_args, **exc_kwargs) from exc

        return wrapper

    return decorator
