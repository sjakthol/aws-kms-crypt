Utility for encrypting and decrypting secrets with the AWS KMS service.

The key features are:
* KMS is only used to generate data encryption keys and the plaintext data
  is never sent to Amazon.
* The utility provides interoperable encryption / decryption interfaces for
  multiple programming languages.

# Usage

## Shell Scripts (Bash)
The shell script at `shell/aws-kms-crypt.sh` provides an interface for shell
scripts to encrypt and decrypt data.

### Requirements
The script uses the AWS CLI for interacting with the KMS service and the `openssl`
command line tool to encrypt the data. The script needs the following commands / tools
to function:

* `aws`
* `base64`
* `cut`
* `jq`
* `od`
* `openssl`
* `sed`

### Encrypting Data
```bash
# No encryption context
echo "my super secret plan" | ./aws-kms-crypt.sh encrypt --kms-key-id alias/common > encrypted-plan.json

# With encryption context
echo "my super secret plan" | ./aws-kms-crypt.sh encrypt --kms-key-id alias/common --encryption-context type=plan,entity=admins > encrypted-plan.json
```

### Decrypting Data
```bash
$ cat encrypted-plan.json | ./aws-kms-crypt.sh decrypt
my super secret plan
```

# How it works?

## Encrypting Data

The following steps are taken when the data is encrypted:

1. A random 16 byte initialization vector is generated with the [GenerateRandom](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateRandom.html) KMS API call
2. A data encryption key for AES-128 algorithm is generated with the [GenerateDataKey](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html)` KMS API call
3. The input data is encrypted locally with AES-128-CBC algorithm using the plaintext version
   of the generated data key together with the generated IV for encryption.
4. The encrypted data, encrypted data key and the initialization vector is outputted into
   a JSON document of following format:
    ```json
    {
      "EncryptedData": "<base64>",
      "EncryptedDataKey": "<base64>",
      "EncryptionContext": {
        "KeyName1": "1",
        "KeyName2": "2"
      },
      "Iv": "<hex>"
    }
    ````

This JSON output can be saved to a file and stored in (semi) publicly available location
as it does not reveal anything about the encrypted data.

## Decrypting the Data
The decryption phase extracts the data from the JSON document the encryption phase
produced and takes the following steps to decrypt the data:

1. The encrypted data key is decrypted using the [Decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html) KMS API call
   to retrieve the plaintext data encryption key
2. The plaintext data key and the IV is used to decrypt the encrypted data locally.
