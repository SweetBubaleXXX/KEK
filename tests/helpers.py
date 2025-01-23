from typing import AsyncIterator


def async_iterator(text: bytes):
    async def generator() -> AsyncIterator[bytes]:
        for byte in text:
            yield byte.to_bytes(1, "big")

    return generator()
