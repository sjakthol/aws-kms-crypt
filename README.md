# aws-kms-crypt

Library for encrypting and decrypting secrets within the AWS ecosystem.

* [Features](#features)
* [Installations](#installation)
* [Usage](#usage)
  * [General Prerequisites](#usage-general)
  * [Shell](#usage-shell)
  * [Node](#usage-node)
  * [Python](#usage-python)
  * [Rust](#usage-rust)
* [How it Works?](#details)

<a name="features"></a>

# Features

* **Interoperable** - Interoperable implementations for Bash, NodeJS, Python and Rust.
* **Secure** - AES encryption with KMS generated data keys ([details](#details)).
* **Simple** - Simple API for encrypting and decrypting sensitive data from all supported languages.

<a name="installation"></a>

# Installation

## Shell

```
curl -LO https://raw.githubusercontent.com/sjakthol/aws-kms-crypt/master/shell/aws-kms-crypt.sh && chmod +x aws-kms-crypt.sh
```

## NodeJS
```
npm install aws-kms-crypt
```

## Python
```
pip install aws-kms-crypt
```

## Rust
Experimental. Not available at the moment.

<a name="usage"></a>

# Usage

<a name="usage-general"></a>

## General Prerequisites

All implementations require access to AWS credentials.

When encrypting data, the credentials must allow the following actions:

* `kms:GenerateDataKey`
* `kms:GenerateRandom`

When decrypting data, the credentials must allow the following actions:

* `kms:Decrypt`

In both cases, the access can (and should in the case of `kms:Decrypt`) be
further limited with IAM policy conditions (see [here](https://docs.aws.amazon.com/kms/latest/developerguide/policy-conditions.html)
for details).

<a name="usage-shell"></a>

## Shell Scripts (Bash)
The shell script at `shell/aws-kms-crypt.sh` provides an interface for shell
scripts to encrypt and decrypt data. The script needs the following commands /
tools to function:

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
echo -n "secretp4ssw0rd!" | ./aws-kms-crypt.sh encrypt --kms-key-id alias/common > encrypted-plan.json

# With encryption context
echo -n "secretp4ssw0rd!" | ./aws-kms-crypt.sh encrypt --kms-key-id alias/common --encryption-context type=plan,entity=admins > encrypted-plan.json
```

### Decrypting Data
```bash
$ cat encrypted-plan.json | ./aws-kms-crypt.sh decrypt
secretp4ssw0rd!
```

<a name="usage-node"></a>

## Node
The `nodejs` directory contains a Node package that implements the KMS based encryption
and decryption functionality.

A recent version of Node (>= 4) is required.

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
<a name="usage-python"></a>
The `python` directory contains a Python package that implements the KMS based encryption
and decryption functionality. The module has been tested to work with both Python 2.7 and
Python 3.5.

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

<a name="usage-rust"></a>

## Rust
The `rust` directory contains a rust crate that implements KMS based decryption
functionality.

### Encrypting Data
Encryption in Rust is not supported at the moment.

### Decrypting Data
Here's a full example that uses [serde_json](https://crates.io/crates/serde_json)
to deserialize the JSON encoded secret into a struct:

```rust
extern crate aws_kms_crypt;
extern crate serde_json;

fn main() {
    let raw = r#"{
        "EncryptedData": "vRhu+D5LrwNctyhxDvUoqL51YH2LclgUKtDz/2Nxy6Y=",
        "EncryptedDataKey": "<snip>KBFRpvDvpXNXu3e/tTO6Jfi",
        "EncryptionContext": {
            "entity": "admin"
        },
        "Iv": "31bf06a8e0d15a26f1325da6f4f33a9c"
    }"#;

    let data: aws_kms_crypt::EncryptedSecret = serde_json::from_str(raw).unwrap();
    let options = aws_kms_crypt::Options {
        region: "eu-west-1".to_owned()
    };

    let res = aws_kms_crypt::decrypt(&data, &options);
    println!("Secret is: {:?}", res.unwrap());
}
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
