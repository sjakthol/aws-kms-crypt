Utility for encrypting and decrypting secrets with the AWS KMS service.

# Installation

Install from PyPI with pip

```bash
pip install aws-kms-crypt
```

# Usage

Requires Python 3.8 or newer.

```python
import kmscrypt

# Encrypting Data
>>> result = kmscrypt.encrypt('secretp4ssw0rd!', key_id='alias/common', encryption_context={
...     'purpose': 'automation'
... })
>>> result
{
    "EncryptedDataKey": "AQIDAHhyrbU/fPcQ+a8pJiYC<snip>",
    "Iv": "689806fe9d571afeffa4c7c24247c766",
    "EncryptedData": "YRjZDQ2KzcEAZqUy7SpWWA==",
    "EncryptionContext": {
        "purpose": "automation"
    }
}

# Decrypting data
>>> kmscrypt.decrypt(result)
b'secretp4ssw0rd!'
```

# Changelog

## v3.0.0 (2024-01-31)

* Dropped Python 3.7 support.

## v2.0.0 (2022-09-15)

* Dropped Python 3.6 support.

## v1.0.0 (2021-09-25)

* Dropped Python 2.7 support.
* Replaced [pycrypto](https://www.dlitz.net/software/pycrypto/) with [cryptography](https://cryptography.io/en/latest/).

# License

MIT