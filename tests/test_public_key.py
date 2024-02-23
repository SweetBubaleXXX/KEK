from kek import PublicKey


def test_load_key(serialized_public_key: bytes, key_size: int):
    key = PublicKey.load(serialized_public_key)
    assert isinstance(key, PublicKey)
    assert key.key_size == key_size


def test_serialize_key(public_key: PublicKey, serialized_public_key: bytes):
    result = public_key.serialize()
    assert result == serialized_public_key


def test_verify_message(
    message_signature: bytes,
    message_for_signing: bytes,
    public_key: PublicKey,
):
    is_valid = public_key.verify(message_signature, message_for_signing)
    assert is_valid
