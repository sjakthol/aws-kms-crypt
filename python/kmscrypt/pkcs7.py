"""
Helper module for handling PKCS#7 padding.
"""


class InvalidPaddingException(ValueError):
    """Exception caused by padding not conforming to the PKCS#7 standard."""
    pass


def _chr(i):
    """Converts an int to 1-char byte string.

    This function is used for python2 and python3 compatibility. See
    http://python-future.org/compatible_idioms.html#byte-string-literals

    Args:
        i: The integer to convert.

    Returns:
        A 1-char byte string with the input value as the byte value.
    """
    return chr(i).encode('latin-1')


def _ord(i):
    """Converts a 1-char byte string to int.

    This function is used for python2 and python3 compatibility
    that can also handle an integer input.

    Args:
        i: The 1-char byte string to convert to an int.

    Returns:
        The byte string value as int or i if the input was already an
        integer.

    """
    if isinstance(i, int):
        return i
    else:
        return ord(i)


def pad(data, block_size=16):
    """Pads data PKCS#7.

    Args:
        data: The data to pad with PKCS#7.
        block_size: The number of bytes to align the data to (from 2 to 255 inclusive).

    Returns:
        The padded version of the data.

    Raises:
        TypeError: If the arguments have invalid types.
        ValueError: If the block_size is not in valid range.
    """

    if not isinstance(data, bytes):
        raise TypeError('data is not a byte array')

    if not isinstance(block_size, int):
        raise TypeError('block_size must be an integer')

    if block_size < 2 or block_size > 255:
        raise ValueError('block_size must be between 2 and 255')

    pad_len = 16 - (len(data) % 16)
    return data + (_chr(pad_len) * pad_len)


def unpad(data, block_size=16):
    """Removes PKCS#7 padding from data

    Args:
        data: The data to unpad.
        block_size: The number of bytes the data should be aligned to (from 2 to 255 inclusive).

    Returns:
        The unpadded version of the data.

    Raises:
        TypeError: If the arguments have invalid types.
        InvalidPaddingException: If the padding does not conform to PKCS#7 standard.
    """

    if not isinstance(data, bytes):
        raise TypeError('data is not a byte array')

    if len(data) < block_size:
        raise InvalidPaddingException('data is too short to be padded (%i vs %i bytes)' % (len(data), block_size))

    if len(data) % block_size:
        raise InvalidPaddingException('data has invalid block size: %i not multiple of %i' % (len(data), block_size))

    pad_len = _ord(data[-1])

    padding = data[-pad_len:]
    expected = _chr(pad_len) * pad_len

    # Validate the padding
    if padding != expected:
        raise InvalidPaddingException('padding is invalid: got %s, expected %s' % (padding, expected))

    return data[:-pad_len]
