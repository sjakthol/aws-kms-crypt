"""Module for various helper functions needed for py2/3 compatibility."""

import base64
import binascii


def _ensure_unicode(data):
    """Ensures that bytes are decoded.

    Args:
        data: The data to decode if not already decoded.

    Returns:
        The decoded data.
    """
    if isinstance(data, bytes):
        data = data.decode('UTF-8')

    return data


def b64encode(data):
    """Helper to base64 encode the given bytes.

    This is needed to make the output an str for both py2 and py3.

    Args:
        data: The bytes to encode

    Return:
        The encoded data as unicode in py2 and str in py3
    """
    return _ensure_unicode(base64.b64encode(data))


def hexlify(data):
    """Helper to hexlify the given bytes.

    This is needed to make the output an str for both py2 and py3.

    Args:
        data: The bytes to encode

    Return:
        The encoded data as unicode in py2 and str in py3
    """

    return _ensure_unicode(binascii.hexlify(data))
