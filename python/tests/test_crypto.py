import base64
import binascii
import boto3
import json
import pytest

import kmscrypt
import kmscrypt.helpers

TEST_PLAINTEXT_KEY = binascii.unhexlify('00968820dfc11ee7816ac942b3980941')
TEST_ENCRYPTED_KEY = binascii.unhexlify('e05c35df8681f98b1fcee59bcc8e0d2e')
TEST_DATA = {
    'EncryptedData': 'aVA+gdKlKhurE791OKA7Cg==',
    'EncryptedDataKey': '4Fw134aB+YsfzuWbzI4NLg==',
    'EncryptionContext': {
        'entity': 'test'
    },
    'Iv': 'd16490194f8b57bb1c1d6ba8ba10125e'
}


def test_decrypt_successful(monkeypatch):
    def mock_decrypt(CiphertextBlob, EncryptionContext):
        assert CiphertextBlob == base64.b64decode(TEST_DATA['EncryptedDataKey'])

        assert 'entity' in EncryptionContext
        assert EncryptionContext['entity'] == 'test'

        return {
            'Plaintext': TEST_PLAINTEXT_KEY
        }

    kms_mock = boto3.client('kms')
    kms_mock.decrypt = mock_decrypt

    monkeypatch.setattr(boto3, 'client', lambda s: kms_mock)

    res = kmscrypt.decrypt(TEST_DATA)

    assert res == 'hello'


@pytest.mark.parametrize('data', [
    b'hello world!',
    'hello_world!'
])
def test_encrypt(monkeypatch, data):
    def mock_generate_data_key(KeyId=None, KeySpec=None, EncryptionContext={}):
        assert KeyId == 'alias/test'
        assert KeySpec == 'AES_128'

        assert 'entity' in EncryptionContext
        assert EncryptionContext['entity'] == 'test_encrypt'

        return {
            'CiphertextBlob': TEST_ENCRYPTED_KEY,
            'Plaintext': base64.b64encode(TEST_PLAINTEXT_KEY)
        }

    kms_mock = boto3.client('kms')
    kms_mock.generate_data_key = mock_generate_data_key
    monkeypatch.setattr(boto3, 'client', lambda s: kms_mock)

    res = kmscrypt.encrypt(data, key_id='alias/test', encryption_context={'entity': 'test_encrypt'})

    assert isinstance(res, dict)
    assert 'EncryptedData' in res
    assert res['EncryptedDataKey'] == kmscrypt.helpers.b64encode(TEST_ENCRYPTED_KEY)

    # The result should be JSON dumpable
    assert json.dumps(res)
