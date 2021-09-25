"""Simple CLI to encrypt and decrypt secrets with AWS KMS."""
import fileinput
import json
import sys

from kmscrypt.crypto import decrypt, encrypt


def main():
    """CLI entrypoint."""
    data = "".join(list(fileinput.input()))

    try:
        parsed = json.loads(data)
    except ValueError:
        parsed = {}

    if "EncryptedData" in parsed:
        print("Decrypting data...", file=sys.stderr)
        print(decrypt(parsed))
    else:
        print("Encrypting data...", file=sys.stderr)
        print(json.dumps(encrypt(data, key_id="alias/common"), indent=2))


if __name__ == "__main__":
    main()
