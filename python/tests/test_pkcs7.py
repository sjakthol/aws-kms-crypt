import pytest

from kmscrypt import pkcs7


@pytest.mark.parametrize('data,block_size,output', [
    (b'', 16, b'\x10' * 16),
    (b'A', 16, b'A' + (b'\x0f' * 15)),
    (b'AAAAAAAAAAAAAAAA', 16, b'AAAAAAAAAAAAAAAA' + (b'\x10' * 16))
], ids=['empty string', 'unaligned string', 'aligned string'])
def test_valid_pad(data, block_size, output):
    assert pkcs7.pad(data, block_size=block_size) == output


@pytest.mark.parametrize('data,block_size,expected_exception', [
    (123, 16, TypeError),
    (b'', 15.123, TypeError),
    (b'', 0, ValueError),
    (b'', 256, ValueError),
])
def test_invalid_pad(data, block_size, expected_exception):
    with pytest.raises(expected_exception):
        pkcs7.pad(data, block_size)


@pytest.mark.parametrize('data,block_size,output', [
    (b'\x10' * 16, 16, b''),
    (b'A' + (b'\x0f' * 15), 16, b'A'),
    (b'AAAAAAAAAAAAAAAA' + (b'\x10' * 16), 16, b'AAAAAAAAAAAAAAAA'),
], ids=['empty string', 'unaligned string', 'aligned string'])
def test_valid_unpad(data, block_size, output):
    assert pkcs7.unpad(data, block_size=block_size) == output


@pytest.mark.parametrize('data,block_size,expected_exception', [
    (123, 16, TypeError),
    (b'', 16, pkcs7.InvalidPaddingException),
    (b'\x01' * 17, 16, pkcs7.InvalidPaddingException),
    (b'AAAAAAAAAAAAAA\x01\x02', 16, pkcs7.InvalidPaddingException),
])
def test_invalid_unpad(data, block_size, expected_exception):
    with pytest.raises(expected_exception):
        pkcs7.unpad(data, block_size)


def test_pad_then_unpad():
    data = b'Hello World!'
    assert data == pkcs7.unpad(pkcs7.pad(data))
