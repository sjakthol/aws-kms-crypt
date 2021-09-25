"""Main module containing encryption and decryption routines."""

import base64
import binascii
import os

from typing import TYPE_CHECKING, Dict, Union

import boto3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

if TYPE_CHECKING:
    from typing_extensions import Final, TypedDict
else:
    Final = object
    TypedDict = object

AES_IV_BYTES = 16
AES_KEY_BYTES = 16  # 128 bits
AES_BLOCK_SIZE = 128  # bits
AES_KEY_SPEC: Final = "AES_128"


class EncryptedData(TypedDict):
    """Dict containing encrypted data and information needed to decrypt it."""

    EncryptedData: str
    EncryptedDataKey: str
    EncryptionContext: Dict[str, str]
    Iv: str


def decrypt(data: EncryptedData, session: boto3.Session = None) -> bytes:
    """Decrypts previously encrypted data.

    Args:
        data: The (JSON) object returned by earlier call to encrypt().
        session: boto3.Session object to use for KMS calls.

    Returns:
        The encrypted secret as bytes.
    """
    # Decode payload
    ciphertext = base64.b64decode(data["EncryptedData"])
    encrypted_data_key = base64.b64decode(data["EncryptedDataKey"])
    initialization_vector = binascii.unhexlify(data["Iv"])

    # Decrypt key
    kms = (session or boto3.Session()).client("kms")
    res = kms.decrypt(
        CiphertextBlob=encrypted_data_key,
        EncryptionContext=data["EncryptionContext"],
    )
    key = res["Plaintext"]

    # Decrypt data
    cipher = Cipher(algorithms.AES(key), modes.CBC(initialization_vector))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad data
    unpadder = padding.PKCS7(AES_BLOCK_SIZE).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext


def encrypt(
    data: Union[str, bytes],
    key_id: str,
    encryption_context: Dict[str, str] = None,
    session: boto3.Session = None,
) -> EncryptedData:
    """Encrypts a given data string.

    Args:
        data: The secret to encrypt. It can be str / unicode (py2) or
            str / bytes (py3).
        key_id: ID, ARN, alias or alias ARN of the KMS key to encrypt the
            data with
        encryption_context: Optional encryption context (key-value dict)
            for KMS
        session: boto3.Session object to use for KMS calls.

    Returns:
        A dictionary containing the data that is required to decrypt the
        secret.
    """

    if not encryption_context:
        encryption_context = {}

    # Generate key
    kms = (session or boto3.Session()).client("kms")
    res = kms.generate_data_key(
        KeyId=key_id, KeySpec=AES_KEY_SPEC, EncryptionContext=encryption_context
    )
    key = res["Plaintext"]

    # And initialization vector
    initialization_vector = os.urandom(16)

    # Ensure data is bytes
    if isinstance(data, str):
        data = data.encode("utf-8")

    # Pad data
    padder = padding.PKCS7(AES_BLOCK_SIZE).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Encrypt data
    cipher = Cipher(algorithms.AES(key), modes.CBC(initialization_vector))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return {
        "EncryptedData": base64.b64encode(ciphertext).decode(),
        "EncryptedDataKey": base64.b64encode(res["CiphertextBlob"]).decode(),
        "EncryptionContext": encryption_context,
        "Iv": binascii.b2a_hex(initialization_vector).decode(),
    }
