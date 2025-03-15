# KEK

![Python](https://img.shields.io/badge/Python->=3.10-orange)
![License](https://img.shields.io/pypi/l/gnukek)

## Installation

To install KEK:

```sh
pip install gnukek
```

## Usage

### Generating a Key Pair

```python
from gnukek import KeyPair

key_pair = KeyPair.generate(key_size=2048)
```

### Serializing Keys

```python
private_key = key_pair.serialize(password=b"your_password")
public_key = key_pair.public_key.serialize()
```

### Loading Keys

```python
loaded_key_pair = KeyPair.load(private_key, password=b"your_password")
loaded_public_key = PublicKey.load(public_key)
```

### Encrypting and Decrypting Messages

```python
message = b"Secret message"
encryptor = key_pair.public_key.get_encryptor()
encrypted_message = encryptor.encrypt(message)

decrypted_message = key_pair.decrypt(encrypted_message)
```

### Encrypting and Decrypting Streams

```python
# Encrypting a stream
with open("path/to/input/file", "rb") as input_file:
    encryptor = key_pair.public_key.get_encryptor()
    for chunk in encryptor.encrypt_stream(input_file):
        output_file.write(chunk)

# Decrypting a stream
with open("path/to/encrypted/file", "rb") as encrypted_file:
    for chunk in key_pair.decrypt_stream(encrypted_file):
        decrypted_file.write(chunk)
```

### Signing and Verifying Messages

```python
signature = key_pair.sign(message)
is_valid = key_pair.public_key.verify(signature, message=message)
```

### Encrypted data consists of:

| **Content**                      | **Length**                                                                                                      |
| -------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| Key version                      | _1 byte_                                                                                                        |
| Key id                           | _8 bytes_                                                                                                       |
| Encrypted symmetric key          | _Equal to key length (256-512 bytes)_                                                                           |
| Data encrypted via symmetric key | _Slightly larger than the length of original data and multiple of block length (<= len(original) + len(block))_ |

## License

This project is licensed under the GNU General Public License v3.0. See the [LICENSE](LICENSE) file for details.
