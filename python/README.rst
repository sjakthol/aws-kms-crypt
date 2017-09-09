Utility for encrypting and decrypting secrets with the AWS KMS service.

Installation
============
.. code-block:: bash

    pip install aws-kms-crypt

Usage
=====
You will need to configure credentials and AWS region for boto3 to use this library. Please
refer to the `Boto3 Documentation <https://boto3.readthedocs.io/en/latest/guide/quickstart.html#configuration>`_
for details.

.. code-block:: python

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
    'secretp4ssw0rd!'
