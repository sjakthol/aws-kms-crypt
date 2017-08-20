/* eslint-env mocha */

'use strict'

const chai = require('chai')
const expect = chai.expect

const crypto = require('../lib/crypto')

const TEST_KEY = Buffer.from('00968820dfc11ee7816ac942b3980941', 'hex')
const TEST_IV = Buffer.from('e05c35df8681f98b1fcee59bcc8e0d2e', 'hex')

const VALIDATION_TEST_CASES = [{
  desc: 'valid input',
  input: {
    key: Buffer.from('00968820dfc11ee7816ac942b3980941', 'hex'),
    iv: Buffer.from('e05c35df8681f98b1fcee59bcc8e0d2e', 'hex')
  },

  success: true
}, {
  desc: 'non-buffer key',
  input: {
    key: '00968820dfc11ee7816ac942b3980941',
    iv: Buffer.from('e05c35df8681f98b1fcee59bcc8e0d2e', 'hex')
  },

  success: false
}, {
  desc: 'non-iv key',
  input: {
    key: Buffer.from('e05c35df8681f98b1fcee59bcc8e0d2e', 'hex'),
    iv: '00968820dfc11ee7816ac942b3980941'
  },

  success: false
}, {
  desc: 'key of wrong length',
  input: {
    key: Buffer.from('0000', 'hex'),
    iv: Buffer.from('e05c35df8681f98b1fcee59bcc8e0d2e', 'hex')
  },

  success: false
}, {
  desc: 'iv of wrong length',
  input: {
    key: Buffer.from('e05c35df8681f98b1fcee59bcc8e0d2e', 'hex'),
    iv: Buffer.from('0000', 'hex')
  },

  success: false
}, {
  desc: 'equal iv and key',
  input: {
    key: Buffer.from('e05c35df8681f98b1fcee59bcc8e0d2e', 'hex'),
    iv: Buffer.from('e05c35df8681f98b1fcee59bcc8e0d2e', 'hex')
  },

  success: false
}]

describe('the crypto module', function () {
  describe('validateKeyAndIv method', function () {
    VALIDATION_TEST_CASES.forEach(test => {
      it('should detect ' + test.desc, function () {
        if (test.success) {
          expect(crypto.validateKeyAndIv(test.input.key, test.input.iv)).to.equal(true)
        } else {
          expect(() => crypto.validateKeyAndIv(test.input.key, test.input.iv)).to.throw()
        }
      })
    })
  })

  describe('encrypt method', function () {
    it('throws if message is not a buffer', function () {
      expect(() => crypto.encrypt('test', TEST_KEY, TEST_IV)).to.throw()
    })
  })

  describe('decrypt method', function () {
    it('throws if message is not a buffer', function () {
      expect(() => crypto.decrypt('test', TEST_KEY, TEST_IV)).to.throw()
    })
  })

  it('should be able to decrypt what encrypt outputted', function () {
    const message = Buffer.from('test_message', 'utf8')
    const enc = crypto.encrypt(message, TEST_KEY, TEST_IV)
    const dec = crypto.decrypt(Buffer.from(enc, 'base64'), TEST_KEY, TEST_IV)
    expect(dec).to.equal('test_message')
  })
})
