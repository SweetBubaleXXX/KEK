# KEK
![Python](https://img.shields.io/badge/Python->=3.7-orange)
![Python](https://img.shields.io/badge/cryptography->=35.0.0-green)
![License](https://img.shields.io/pypi/l/gnukek)
![Status](https://img.shields.io/pypi/status/gnukek)
[![Documentation Status](https://readthedocs.org/projects/gnukek/badge/?version=latest)](https://gnukek.readthedocs.io/en/latest/?badge=latest)
[![Tests](https://github.com/SweetBubaleXXX/KEK/actions/workflows/python-package.yml/badge.svg)](https://github.com/SweetBubaleXXX/KEK/actions)

Kinetic Encryption Key

----------

This library provides [symmetric](https://gnukek.readthedocs.io/en/latest/KEK.html#module-KEK.symmetric),
[asymmetric](https://gnukek.readthedocs.io/en/latest/KEK.html#module-KEK.asymmetric) (public key),
[hybrid](https://gnukek.readthedocs.io/en/latest/KEK.html#module-KEK.hybrid) (symmetric + asymmetric) encryption.

It was build using [cryptography](https://cryptography.io/en/latest/) library and has uncomplicated interface.

Algorithms:

- **AES** in **CBC** mode (128-256 bit)

- **RSA** (2048-4096 bit)

----------

[Read the documentation on ReadTheDocs!](https://gnukek.readthedocs.io/en/latest/)

----------

## Installation

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install [KEK](https://pypi.org/project/gnukek/).

```bash
pip install gnukek
```

## Usage

Import key classes:

```python
from KEK.hybrid import PrivateKEK, PublicKEK
```

To generate key:

```python
private_key = PrivateKEK.generate()
```

To generate public key object:

```python
public_key = private_key.public_key
```

To encrypt data:

```python
encrypted = public_key.encrypt(b"byte data")
```

> You can also encrypt data using private key object: `private_key.encrypt()`

To decrypt data:

```python
decrypted = private_key.decrypt(encrypted) # b"byte data"
```

Also supports chunk encryption/decryption:

```python
with open("file", "rb") as input_file, open("file.out", "wb") as output_file:
    for chunk in private_key.encrypt_chunks(input_file, 1024):
        output_file.write(chunk)
```

To sign data:

```python
data = b"byte data"
signature = private_key.sign(data) 
```

To verify signature:

```python
public_key.verify(signature, data) # True
```

Both private and public keys can be serialized in [PEM](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/#pem) encoded
[PKCS8](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/#cryptography.hazmat.primitives.serialization.PrivateFormat.PKCS8) format:

```python
serialized_key = private_key.serialize()
loaded_private_key = PrivateKEK.load(serialized_key)
```

## Hybrid encryption

### How it works?

- Ecryption:

    - Data is encrypted via fresh generated [symmetric key](https://gnukek.readthedocs.io/en/latest/KEK.html#module-KEK.symmetric).

    - Symmetric key is encrypted via public [asymmetric key](https://gnukek.readthedocs.io/en/latest/KEK.html#module-KEK.asymmetric).

- Decryption:

    - Symmetric key is decrypted via private [asymmetric key](https://gnukek.readthedocs.io/en/latest/KEK.html#module-KEK.asymmetric).

    - Data is decrypted via loaded [symmetric key](https://gnukek.readthedocs.io/en/latest/KEK.html#module-KEK.symmetric).

### Encrypted data consists of:

| **Content** | **Length** |
| ----------- | ---------- |
| [Key version](https://gnukek.readthedocs.io/en/latest/KEK.html#KEK.hybrid.PrivateKEK.version) | *1 byte* |
| [Key id](https://gnukek.readthedocs.io/en/latest/KEK.html#KEK.hybrid.PrivateKEK.key_id) | *8 bytes* |
| Encrypted symmetric key | *Equal to key length (256-512 bytes)* |
| Data encrypted via symmetric key | *Slightly larger than the length of original data and multiple of block length (<= len(original) + len(block))* |

## License

[GPLv3 license](https://github.com/SweetBubaleXXX/KEK/blob/main/LICENSE)
