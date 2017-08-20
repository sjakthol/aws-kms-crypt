'use strict'

const crypto = require('crypto')

const AES_CBC_IDENTIFIER = 'aes-128-cbc'
const AES_IV_BYTES = 16
const AES_KEY_BYTES = 16

module.exports = {
  /**
   * Decrypts the given message using the given key and iv.
   *
   * @param {Buffer} message the message to decrypt
   * @param {Buffer} key the key to decrypt the data with
   * @param {Buffer} iv the initialization vector to use
   * @return {string} the decrypt message as string
   * @throws {Error} if decryption fails or input is invalid
   */
  decrypt: (message, key, iv) => {
    // Validate the key and iv
    module.exports.validateKeyAndIv(key, iv)

    // Sanity check the message
    if (!Buffer.isBuffer(message) || message.length === 0) {
      throw new Error('Given message is invalid')
    }

    // Decrypt the message
    const cipher = crypto.createDecipheriv(AES_CBC_IDENTIFIER, key, iv)
    return cipher.update(message, undefined, 'utf8') + cipher.final('utf8')
  },

  /**
   * Encrypts the given message with the given key and initialization vector.
   *
   * @param {Buffer} message the message to encrypt
   * @param {Buffer} key the key to encrypt the data with
   * @param {Buffer} iv the initialization vector to use
   * @return {string} the encrypted message as base64 encoded string
   * @throws {Error} if encryption fails or input is invalid
   */
  encrypt: (message, key, iv) => {
    // Validate the key and iv
    module.exports.validateKeyAndIv(key, iv)

    // Sanity check the message
    if (!Buffer.isBuffer(message) || message.length === 0) {
      throw new Error('Given message is invalid')
    }

    // Encrypt the message
    const cipher = crypto.createCipheriv(AES_CBC_IDENTIFIER, key, iv)
    return cipher.update(message, 'utf-8', 'base64') + cipher.final('base64')
  },

  validateKeyAndIv: (key, iv) => {
    if (!Buffer.isBuffer(key)) {
      throw new TypeError('Encryption key must be a Buffer')
    }

    if (!Buffer.isBuffer(iv)) {
      throw new TypeError('IV must be a Buffer')
    }

    if (key.length !== AES_KEY_BYTES) {
      throw new Error('Encryption key must be ' + AES_KEY_BYTES + ' bytes')
    }

    if (iv.length !== AES_IV_BYTES) {
      throw new Error('IV must be ' + AES_IV_BYTES + ' bytes')
    }

    if (iv.compare(key) === 0) {
      throw new Error('Key and IV cannot be the same!')
    }

    return true
  }
}
