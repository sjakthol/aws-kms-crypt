# pylint: disable=missing-function-docstring,missing-module-docstring,redefined-outer-name
import json

import boto3
import moto
import pytest

import kmscrypt


@pytest.fixture(autouse=True)
def mock_aws_env(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-north-1")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")


@pytest.fixture()
def mock_kms_key():
    with moto.mock_kms():
        kms = boto3.client("kms")
        yield kms.create_key()["KeyMetadata"]["KeyId"]


@pytest.mark.parametrize("data", [b"hello world!", "hello_world!"])
def test_encrypt_decrypt(mock_kms_key, data):
    encrypted = kmscrypt.encrypt(data, mock_kms_key, encryption_context={"Foo": "Bar"})
    assert json.dumps(encrypted)
    assert encrypted["EncryptionContext"] == {"Foo": "Bar"}

    decrypted = kmscrypt.decrypt(encrypted)
    assert decrypted == data if isinstance(data, bytes) else data.encode()
