import unittest

from KEK import symmetric, asymmetric, hybrid


class TestSymmetricKey(unittest.TestCase):
    def setUp(self):
        self.key_size = symmetric.SymmetricKey.key_sizes[-1]
        self.key = symmetric.SymmetricKey.generate(self.key_size)

    def test_key_size_method(self):
        self.assertEqual(self.key.key_size, self.key_size)

    def test_encryption(self):
        encrypted_data = self.key.encrypt(b"byte data")
        self.assertIsInstance(encrypted_data, bytes)

    def test_decryption(self):
        data = b"byte data"
        encrypted_data = self.key.encrypt(data)
        decrypted_data = self.key.decrypt(encrypted_data)
        self.assertEqual(decrypted_data, data)

    def test_constructor(self):
        key = self.key.key
        iv = self.key.iv
        new_key = symmetric.SymmetricKey(key, iv)
        data = b"byte data"
        self.assertEqual(self.key.encrypt(data), new_key.encrypt(data))


class TestAsymmetricKey(unittest.TestCase):
    def setUp(self):
        self.key_size = asymmetric.PrivateKey.key_sizes[1]
        self.private_key = asymmetric.PrivateKey.generate(self.key_size)

    def test_key_size_method(self):
        self.assertEqual(self.private_key.key_size, self.key_size)

    def test_public_key_creation(self):
        public_key = self.private_key.public_key
        self.assertIsInstance(public_key, asymmetric.PublicKey)

    def test_private_key_serialization(self):
        serialized_data = self.private_key.serialize(b"password")
        loaded_key = asymmetric.PrivateKey.load(serialized_data, b"password")
        self.assertIsInstance(loaded_key, asymmetric.PrivateKey)

    def test_public_key_serialization(self):
        public_ley = self.private_key.public_key
        serialized_data = public_ley.serialize()
        loaded_key = asymmetric.PublicKey.load(serialized_data)
        self.assertIsInstance(loaded_key, asymmetric.PublicKey)

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


if __name__ == "__main__":
    unittest.main()
