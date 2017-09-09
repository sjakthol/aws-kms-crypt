"""Main module containing encryption and decryption routines."""

import base64
import binascii
import copy

import boto3
from Crypto import Random
from Crypto.Cipher import AES

import kmscrypt.pkcs7
import kmscrypt.helpers

AES_IV_BYTES = 16
AES_KEY_BYTES = 16  # 128 bits
AES_KEY_SPEC = 'AES_128'
AES_MODE = AES.MODE_CBC


def decrypt(data):
    """Decrypts previously encrypted data.

    Args:
        data: The (JSON) object returned by the encryption routine. The keys and
            values of this dict should be unicode / str (py2) or str (py3). It
            can be safely loaded with, for example, json.load() or stored as a
            dict alongside the code.

    Returns:
        The encrypted secret as an unicode string.
    """
    kms = boto3.client('kms')
    res = kms.decrypt(
        CiphertextBlob=base64.b64decode(data['EncryptedDataKey']),
        EncryptionContext=data['EncryptionContext']
    )

    key = res['Plaintext']
    iv = binascii.unhexlify(data['Iv'])

    cipher = AES.new(key, AES_MODE, iv)
    ciphertext = base64.b64decode(data['EncryptedData'])
    plaintext = cipher.decrypt(ciphertext)

    return kmscrypt.pkcs7.unpad(plaintext, block_size=AES_KEY_BYTES).decode('UTF-8')


def encrypt(data, key_id, encryption_context={}):
    """Encrypts a given data string.

    Args:
        data: The secret to encrypt. It can be str / unicode (py2) or
            str / bytes (py3).
        key_id: ID, ARN, alias or alias ARN of the KMS key to encrypt the
            data with
        encryption_context: Optional encryption context (key-value dict)
            for KMS

    Returns:
        A dictionary containing the data that is required to decrypt the
        secret.
    """

    kms = boto3.client('kms')
    res = kms.generate_data_key(KeyId=key_id, KeySpec=AES_KEY_SPEC, EncryptionContext=encryption_context)

    key = res['Plaintext']
    iv = Random.new().read(16)

    if not isinstance(data, bytes):
        data = data.encode('UTF-8')

    message = kmscrypt.pkcs7.pad(data, block_size=AES_KEY_BYTES)

    cipher = AES.new(key, AES_MODE, iv)
    ciphertext = cipher.encrypt(message)

    return {
        'EncryptedData': kmscrypt.helpers.b64encode(ciphertext),
        'EncryptedDataKey': kmscrypt.helpers.b64encode(res['CiphertextBlob']),
        'EncryptionContext': copy.copy(encryption_context),
        'Iv': kmscrypt.helpers.hexlify(iv)
    }
