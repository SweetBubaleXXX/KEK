from typing import AsyncIterator


def async_iterator(text: bytes):
    async def generator() -> AsyncIterator[bytes]:
        for byte in text:
            yield int.to_bytes(byte)

    return generator()
