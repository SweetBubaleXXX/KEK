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
        self.assertTrue(isinstance(encrypted_data, bytes))

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


if __name__ == "__main__":
    unittest.main()