from __future__ import print_function
from kmscrypt.crypto import decrypt, encrypt  # noqa: F401

if __name__ == '__main__':
    import fileinput
    import json
    import sys

    data = ''.join([line for line in fileinput.input()])

    try:
        parsed = json.loads(data)
    except ValueError as e:
        parsed = {}

    if 'EncryptedData' in parsed:
        print('Decrypting data...', file=sys.stderr)
        print(decrypt(parsed))
    else:
        print('Encrypting data...', file=sys.stderr)
        print(json.dumps(encrypt(data, key_id='alias/common'), indent=2))
