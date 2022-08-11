import unittest
from io import BytesIO
from typing import Type

from KEK import asymmetric, base, hybrid


class TestAsymmetricKey(unittest.TestCase):
    private_key_class: Type[base.BasePrivateKey] = asymmetric.PrivateKey
    public_key_class: Type[base.BasePublicKey] = asymmetric.PublicKey

    def setUp(self):
        self.key_size = self.private_key_class.key_sizes[1]
        self.private_key = self.private_key_class.generate(self.key_size)

    def test_key_size_method(self):
        self.assertEqual(self.private_key.key_size, self.key_size)

    def test_public_key_creation(self):
        public_key = self.private_key.public_key
        self.assertIsInstance(public_key, self.public_key_class)

    def test_private_key_serialization(self):
        serialized_data = self.private_key.serialize(b"password")
        loaded_key = self.private_key_class.load(serialized_data, b"password")
        self.assertIsInstance(loaded_key, self.private_key_class)

    def test_public_key_serialization(self):
        public_key = self.private_key.public_key
        serialized_data = public_key.serialize()
        loaded_key = self.public_key_class.load(serialized_data)
        self.assertIsInstance(loaded_key, self.public_key_class)

    def test_private_key_first_line_attr(self):
        serialized_data = self.private_key.serialize()
        first_line = serialized_data.splitlines()[0]
        self.assertEqual(first_line, self.private_key_class.first_line)

    def test_public_key_first_line_attr(self):
        serialized_data = self.private_key.public_key.serialize()
        first_line = serialized_data.splitlines()[0]
        self.assertEqual(first_line, self.public_key_class.first_line)

    def test_is_encrypted_method(self):
        encrypted_serialized_data = self.private_key.serialize(b"password")
        is_encrypted = self.private_key_class.is_encrypted(
            encrypted_serialized_data
        )
        self.assertTrue(is_encrypted)

    def test_is_encrypted_method_for_unencrypted_key(self):
        serialized_data = self.private_key.serialize()
        is_encrypted = self.private_key_class.is_encrypted(serialized_data)
        self.assertFalse(is_encrypted)

    def test_decryption(self):
        data = b"byte data"
        encrypted_data = self.private_key.encrypt(data)
        decrypted_data = self.private_key.decrypt(encrypted_data)
        self.assertEqual(decrypted_data, data)

    def test_public_encryption(self):
        data = b"byte data"
        public_key = self.private_key.public_key
        encrypted_data = public_key.encrypt(data)
        decrypted_data = self.private_key.decrypt(encrypted_data)
        self.assertEqual(decrypted_data, data)

    def test_verification(self):
        data = b"byte data"
        signature = self.private_key.sign(data)
        self.assertTrue(self.private_key.public_key.verify(signature, data))


class TestHybridKey(TestAsymmetricKey):
    private_key_class = hybrid.PrivateKEK
    public_key_class = hybrid.PublicKEK

    def test_key_id(self):
        private_id = self.private_key.key_id
        public_id = self.private_key.public_key.key_id
        self.assertEqual(private_id, public_id)

    def test_chunk_encryption(self):
        block_length = self.private_key.block_size // 8
        data = b"byte data" * block_length
        input_stream = BytesIO(data)
        output_stream = BytesIO()
        for chunk in self.private_key.encrypt_chunks(input_stream,
                                                     block_length):
            output_stream.write(chunk)
        encrypted_data = output_stream.getvalue()
        entirely_decrypted = self.private_key.decrypt(encrypted_data)
        self.assertEqual(entirely_decrypted, data)

    def test_chunk_decryption(self):
        block_length = self.private_key.block_size // 8
        data = b"byte data" * block_length
        entirely_encrypted = self.private_key.encrypt(data)
        input_stream = BytesIO(entirely_encrypted)
        output_stream = BytesIO()
        for chunk in self.private_key.decrypt_chunks(input_stream,
                                                     block_length):
            output_stream.write(chunk)
        decrypted_data = output_stream.getvalue()
        self.assertEqual(decrypted_data, data)


if __name__ == "__main__":
    unittest.main()
