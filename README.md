Utility for encrypting and decrypting secrets with the AWS KMS service.

* [Features](#features)
* [Usage](#usage)
  * [Shell](#shell)
  * [Node](#node)
  * [Python](#python)
* [How it Works?](#details)

<a name="features"></a>

# Features

The key features are:
* Simple APIs for encrypting and decrypting sensitive data
* Interoperable implementations for multiple languages (Shell, Node and Python)
* [Envelope Encryption](https://docs.aws.amazon.com/kms/latest/developerguide/workflow.html) with `AES-128-CBC` and KMS generated data keys

<a name="usage"></a>

# Usage

<a name="shell"></a>

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

You also need to configure AWS CLI to have access to credentials that can
`kms:GenerateDataKey`, `kms:GenerateRandom` and `kms:Decrypt` with the
specified KMS key and encryption context.

### Encrypting Data
```bash
# No encryption context
echo "secretp4ssw0rd!" | ./aws-kms-crypt.sh encrypt --kms-key-id alias/common > encrypted-plan.json

# With encryption context
echo "secretp4ssw0rd!" | ./aws-kms-crypt.sh encrypt --kms-key-id alias/common --encryption-context type=plan,entity=admins > encrypted-plan.json
```

### Decrypting Data
```bash
$ cat encrypted-plan.json | ./aws-kms-crypt.sh decrypt
secretp4ssw0rd!
```

<a name="node"></a>

## Node
The `nodejs` directory contains a Node package that implements the KMS based encryption
and decryption functionality.

The package can be installed from NPM:
```
npm install aws-kms-crypt
```

### Requirements
A recent version of Node (>= 4) is required.

You also need to configure the AWS SDK to have access to credentials that can
`kms:GenerateDataKey`, `kms:GenerateRandom` and `kms:Decrypt` with the
specified KMS key and encryption context.

### Encrypting Data
Use the `encrypt()` function of the module to encrypt any stringified data:
```js
const kmscrypt = require('aws-kms-crypt')
kmscrypt.encrypt('secretp4ssw0rd!', {
  key: 'alias/common', // Change your key here
  region: 'eu-west-1', // AWS SDK needs to know this
  encryptionContext: { purpose: 'automation' } // optional, can be left out
}, function (err, result) {
  if (err) {
    return console.log('Encryption failed:', err)
  }

  console.log(JSON.stringify(result, null, 2))
  // Console output:
  // {
  //   "EncryptedData": "DPQ0OZ8auGY6ohQb/pypAHJTAPaQre7RrEtziIhRgB8=",
  //   "EncryptedDataKey": "<snip>CBZogG5a",
  //   "EncryptionContext": {
  //     "purpose": "automation"
  //   },
  //   "Iv": "6f93b293f7f77ddf7525bf43038f01c4"
  // }
})
```

### Decrypting Data
To decrypt previously encrypted data, feed the parsed JSON document
into the `decrypt()` function of the module:
```js
const kmscrypt = require('aws-kms-crypt')
kmscrypt.decrypt({
  'EncryptedData': 'TSHgAb4MYkacM9qtdO5OeLQax6jze3P7+zIeUDpakC4=',
  'EncryptedDataKey': '<snip>KqnVhLZY+8',
  'EncryptionContext': {
    'purpose': 'automation'
  },
  'Iv': '6cfbac80d90df12a6357a8f91b57f907'
}, { region: 'eu-west-1' }, function (err, result) {
  if (err) {
    return console.log('Encryption failed:', err)
  }

  console.log(result)
  // => secretp4ssw0rd!
})
```
## Python
<a name="python"></a>
The `python` directory contains a Python package that implements the KMS based encryption
and decryption functionality.

This package can be installed from PyPi:
```
pip install aws-kms-crypt
```

### Requirements
The module has been tested to work with both Python 2.7 and Python 3.5.

You also need to configure the AWS SDK to have access to credentials that can
`kms:GenerateDataKey`, `kms:GenerateRandom` and `kms:Decrypt` with the
specified KMS key and encryption context.

### Encrypting Data
```python
import kmscrypt

res = kmscrypt.encrypt('secretp4ssw0rd!', key_id='alias/common', encryption_context={
  'purpose': 'automation'
})

# res is now a dict of form
# {
#   'EncryptedData': 'Su00srm/ru5kd9DLDvi0EdEjjBGUrRBJ06vUmL8QHUU=',
#   'EncryptedDataKey': 'AQIDAHhyrbU/fP<snip>',
#   'EncryptionContext': {'purpose': 'automation'},
#   'Iv': 'd07acff1e2301c468cd3164b8858e477'
# }
```

### Decrypting Data
```python
secret = kmscrypt.decrypt(res)
print(secret) # => secretp4ssw0rd!
```

<a name="details"></a>

# How it works?

## Encrypting Data

The following steps are taken when the data is encrypted:

1. A random 16 byte initialization vector is generated with the [GenerateRandom](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateRandom.html) KMS API
   call (shell) or through a platform-specific randomness API (Node, Python)
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

# Future Work
* Support other algorithms than AES-128-CBC
* Automated testing of interoperability
