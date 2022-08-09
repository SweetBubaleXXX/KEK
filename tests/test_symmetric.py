import unittest

from KEK import symmetric


class TestSymmetricKey(unittest.TestCase):
    def setUp(self):
        self.key_size = symmetric.SymmetricKey.key_sizes[-1]
        self.key = symmetric.SymmetricKey.generate(self.key_size)

    def test_key_size_method(self):
        self.assertEqual(self.key.key_size, self.key_size)

    def test_encryption(self):
        encrypted_data = self.key.encrypt(b"byte data")
        self.assertIsInstance(encrypted_data, bytes)

    def test_chunk_encryption(self):
        part_1 = b"first chunk" * (self.key.block_size//8)
        part_2 = b"second chunk" * (self.key.block_size//8)
        entirely_encrypted = self.key.encrypt(part_1+part_2)
        encrypted_part_1 = self.key.encrypt_chunk(part_1)
        encrypted_part_2 = self.key.encrypt_chunk(part_2, True)
        self.assertEqual(encrypted_part_1+encrypted_part_2, entirely_encrypted)

    def test_decryption(self):
        data = b"byte data"
        encrypted_data = self.key.encrypt(data)
        decrypted_data = self.key.decrypt(encrypted_data)
        self.assertEqual(decrypted_data, data)

    def test_chunk_decryption(self):
        block_length = self.key.block_size // 8
        chunk = b"byte data"
        data = chunk * block_length
        encrypted_data = self.key.encrypt(data)
        decrypted_chunks = []
        decrypted_chunks.append(self.key.decrypt_chunk(
            encrypted_data[:block_length]))
        decrypted_chunks.append(self.key.decrypt_chunk(
            encrypted_data[block_length:], True))
        decrypted_data = b"".join(decrypted_chunks)
        self.assertEqual(decrypted_data, data)

    def test_constructor(self):
        key = self.key.key
        iv = self.key.iv
        new_key = symmetric.SymmetricKey(key, iv)
        data = b"byte data"
        self.assertEqual(self.key.encrypt(data), new_key.encrypt(data))


if __name__ == "__main__":
    unittest.main()
