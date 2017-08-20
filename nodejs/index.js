'use strict'
const AWS = require('aws-sdk')
const crypto = require('./lib/crypto')
const nodecrypto = require('crypto')

const AES_IV_BYTES = 16
const AES_KEY_SPEC = 'AES_128'

module.exports = {

  /**
   * Handler function for the encrypt operation result.
   *
   * @callback encryptCallback
   * @param {Error} err - the reason for a failure (falsy if success)
   * @param {Object} result - the result of the operation
   * @param {string} result.EncryptedData - the encrypted data (base64 encoded)
   * @param {string} result.EncryptedDataKey - encrypted data key (base64 encoded)
   * @param {string} result.EncryptionContext - the encryption context
   * @param {string} result.Iv - the initialization vector (hex encoded)
   */

  /**
   * Encrypts the given data using KMS.
   *
   * @param {string} data - the data to encrypt
   * @param {Object} options - options for this operation
   * @param {Object} [options.encryptionContext={}] - encryption context
   * @param {string} options.key - KMS key ID, ARN, alias or alias ARN
   * @param {string} options.region - AWS region of the key
   * @param {encryptCallback} callback
   */
  encrypt: (data, options, callback) => {
    const kms = new AWS.KMS({ region: options.region })
    const iv = nodecrypto.randomBytes(AES_IV_BYTES)

    kms.generateDataKey({
      EncryptionContext: options.encryptionContext || {},
      KeyId: options.key,
      KeySpec: AES_KEY_SPEC
    }, function (err, res) {
      if (err) {
        return callback(err)
      }

      let result
      try {
        const message = Buffer.from(data, 'utf8')
        const key = Buffer.from(res.Plaintext, 'base64')
        const enc = crypto.encrypt(message, key, iv)
        result = {
          EncryptedData: enc,
          EncryptedDataKey: res.CiphertextBlob.toString('base64'),
          EncryptionContext: options.encryptionContext || {},
          Iv: iv.toString('hex')
        }
      } catch (e) {
        return callback(e)
      }

      callback(null, result)
    })
  },

  /**
   * Handler function for the decrypt operation result.
   *
   * @callback decryptCallback
   * @param {Error} err - the reason for a failure (falsy if success)
   * @param {string} result - the decrypted message
   */

  /**
   * Decrypts a previously encrypted message.
   *
   * @param {Object} data - the output of the encryption stage
   * @param {string} data.EncryptedData - the encrypted data (base64 encoded)
   * @param {string} data.EncryptedDataKey - encrypted data key (base64 encoded)
   * @param {string} data.EncryptionContext - the encryption context
   * @param {string} data.Iv - the initialization vector (hex encoded)
   * @param {Object} options - options for the operation
   * @param {string} options.region - AWS region of the key
   * @param {decryptCallback} callback
   */
  decrypt: (data, options, callback) => {
    const kms = new AWS.KMS({ region: options.region })
    kms.decrypt({
      CiphertextBlob: Buffer.from(data.EncryptedDataKey, 'base64'),
      EncryptionContext: data.EncryptionContext
    }, function (err, res) {
      if (err) {
        return callback(err)
      }

      let result
      try {
        const key = res.Plaintext
        const iv = Buffer.from(data.Iv, 'hex')
        const message = Buffer.from(data.EncryptedData, 'base64')
        result = crypto.decrypt(message, key, iv)
      } catch (e) {
        return callback(e)
      }

      callback(null, result)
    })
  }
}
