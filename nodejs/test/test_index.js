/* eslint-env mocha */

'use strict'

const chai = require('chai')
const expect = chai.expect
const sinon = require('sinon')
const sinonChai = require('sinon-chai')
chai.use(sinonChai)

const index = require('../index')
const AWS = require('aws-sdk')
AWS.KMS = sinon.stub()
const generateDataKeyStub = AWS.KMS.prototype.generateDataKey = sinon.stub()
const decryptStub = AWS.KMS.prototype.decrypt = sinon.stub()

const TEST_PLAINTEXT_KEY = Buffer.from('00968820dfc11ee7816ac942b3980941', 'hex')
const TEST_ENCRYPTED_KEY = Buffer.from('e05c35df8681f98b1fcee59bcc8e0d2e', 'hex')
const TEST_DATA = {
  EncryptedData: 'mRio/6iZ0C0xCRQrvhAvLIgnPda6Cc/0s8YPyRCkanc=',
  EncryptedDataKey: 'AQIDAHhyrbU/fPcQ+a8pJiYC78j8wop4mw1jqy3CZk35',
  EncryptionContext: {
    entity: 'test'
  },
  Iv: '00968820dfc11ee7816ac942b3980941'
}

describe('the index module', function () {
  describe('encrypt function', function () {
    afterEach(() => {
      generateDataKeyStub.reset()
    })

    it('should encrypt data properly', function (done) {
      generateDataKeyStub.yields(undefined, {
        CiphertextBlob: TEST_ENCRYPTED_KEY,
        Plaintext: TEST_PLAINTEXT_KEY.toString('base64')
      })

      index.encrypt('hello', { key: 'alias/common', region: 'eu-west-1' }, function (err, res) {
        expect(err).to.equal(null)
        expect(res).to.be.an('object')
        expect(res.EncryptedData).to.be.a('string')
        expect(res.EncryptedDataKey).to.equal(TEST_ENCRYPTED_KEY.toString('base64'))
        expect(res.EncryptionContext).to.deep.equal({})
        expect(res.Iv).to.be.a('string')

        expect(generateDataKeyStub).to.have.been.calledWith({
          KeySpec: 'AES_128',
          KeyId: 'alias/common',
          EncryptionContext: {}
        })

        done()
      })
    })

    it('should use encryption context properly', function (done) {
      generateDataKeyStub.yields(undefined, {
        CiphertextBlob: TEST_ENCRYPTED_KEY,
        Plaintext: TEST_PLAINTEXT_KEY.toString('base64')
      })

      const opts = {
        key: 'alias/common',
        region: 'eu-west-1',
        encryptionContext: { abc: 'def' }
      }

      index.encrypt('hello', opts, function (err, res) {
        expect(err).to.equal(null)
        expect(res).to.be.an('object')
        expect(res.EncryptedData).to.be.a('string')
        expect(res.EncryptedDataKey).to.equal(TEST_ENCRYPTED_KEY.toString('base64'))
        expect(res.EncryptionContext).to.deep.equal({ abc: 'def' })
        expect(res.Iv).to.be.a('string')

        expect(generateDataKeyStub).to.have.been.calledWith({
          KeySpec: 'AES_128',
          KeyId: 'alias/common',
          EncryptionContext: { abc: 'def' }
        })

        done()
      })
    })

    it('should call the callback with error if KMS gives an error', function (done) {
      generateDataKeyStub.yields(new Error('hello'))
      index.encrypt('hello', { key: 'alias/common1', region: 'eu-west-1' }, (err, res) => {
        expect(err).to.be.an('error')
        expect(res).to.equal(undefined)
        done()
      })
    })
  })

  describe('decrypt function', function () {
    afterEach(() => {
      decryptStub.reset()
    })

    it('should call the callback with error if KMS gives an error', function (done) {
      decryptStub.yields(new Error('hello'))
      index.decrypt(TEST_DATA, { region: 'eu-west-1' }, (err, res) => {
        expect(err).to.be.an('error')
        expect(res).to.equal(undefined)
        done()
      })
    })

    it('should decrypt data properly', function (done) {
      decryptStub.yields(undefined, {
        Plaintext: TEST_PLAINTEXT_KEY
      })

      const message = {
        EncryptedData: 'aVA+gdKlKhurE791OKA7Cg==',
        EncryptedDataKey: '4Fw134aB+YsfzuWbzI4NLg==',
        EncryptionContext: {},
        Iv: 'd16490194f8b57bb1c1d6ba8ba10125e'
      }

      index.decrypt(message, { region: 'eu-west-1' }, function (err, res) {
        expect(err).to.equal(null)
        expect(res).to.be.a('string')
        expect(res).to.equal('hello')

        expect(decryptStub).to.have.been.calledWith({
          CiphertextBlob: Buffer.from(message.EncryptedDataKey, 'base64'),
          EncryptionContext: {}
        })
        done()
      })
    })

    it('should use encryption context properly', function (done) {
      decryptStub.yields(undefined, {
        Plaintext: TEST_PLAINTEXT_KEY
      })

      const message = {
        EncryptedData: 'aVA+gdKlKhurE791OKA7Cg==',
        EncryptedDataKey: '4Fw134aB+YsfzuWbzI4NLg==',
        EncryptionContext: { abc: 'test' },
        Iv: 'd16490194f8b57bb1c1d6ba8ba10125e'
      }

      index.decrypt(message, { region: 'eu-west-1' }, function (err, res) {
        expect(err).to.equal(null)
        expect(res).to.be.a('string')
        expect(res).to.equal('hello')

        expect(decryptStub).to.have.been.calledWith({
          CiphertextBlob: Buffer.from(message.EncryptedDataKey, 'base64'),
          EncryptionContext: { abc: 'test' }
        })
        done()
      })
    })
  })
})
