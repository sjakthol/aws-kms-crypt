Utility for encrypting and decrypting secrets with the AWS KMS service.

## Installation
```
npm install aws-kms-crypt
```

## Usage
Before using the module, you need to ensure that Amazon SDK has access
to AWS credentials that are able to access the KMS key used for encryption
and decryption.

### Encrypting Data

```js
const kmscrypt = require('aws-kms-crypt')

// Encrypting data
kmscrypt.encrypt('secretp4ssw0rd!', {
  key: 'alias/common', // Your key here
  region: 'eu-west-1', // AWS SDK needs to know this
  encryptionContext: { purpose: 'automation' } // optional, can be left out
}, function (err, result) {
  if (err) {
    return console.log('Encryption failed:', err)
  }

  // result = {
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

```js
const kmscrypt = require('aws-kms-crypt')

kmscrypt.decrypt({
  'EncryptedData': 'DPQ0OZ8auGY6ohQb/pypAHJTAPaQre7RrEtziIhRgB8=',
  'EncryptedDataKey': '<snip>CBZogG5a',
  'EncryptionContext': {
    'purpose': 'automation'
  },
  'Iv': '6f93b293f7f77ddf7525bf43038f01c4'
}, { region: 'eu-west-1' }, function (err, result) {
  if (err) {
    return console.log('Decryption failed:', err)
  }

  console.log(result)
  // => secretp4ssw0rd!
})
```
