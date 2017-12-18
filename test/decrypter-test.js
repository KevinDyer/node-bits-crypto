(() => {
  'use strict';

  const path = require('path');
  const fs = require('fs');
  const chai = require('chai');
  const {PassThrough} = require('stream');
  const Decrypter = require('./../src/decrypter');

  const ENCRYPTION_KEY_FILEPATH = path.join(__dirname, './fixtures/keys/test-key.pem');
  const SIGNATURE_KEY_FILEPATH = path.join(__dirname, './fixtures/keys/signature-key.pub');
  const INPUT_FILEPATH = path.join(__dirname, './fixtures/random-number-1.0.0.mod');

  const expect = chai.expect;

  describe('Decrypter', () => {
    let encryptionKey = null;
    before('Read encryption key', (done) => {
      fs.readFile(ENCRYPTION_KEY_FILEPATH, (err, data) => {
        if (err) {
          done(err);
        } else {
          encryptionKey = data;
          done();
        }
      });
    });

    let signatureKey = null;
    before('Read signature key', (done) => {
      fs.readFile(SIGNATURE_KEY_FILEPATH, (err, data) => {
        if (err) {
          done(err);
        } else {
          signatureKey = data;
          done();
        }
      });
    });

    describe('decrypt', () => {
      let decrypter = null;
      beforeEach('Create decrypter', () => {
        decrypter = new Decrypter();
      });

      function callDecrypt(decrypter, ...params) {
        return function decrypt() {
          decrypter.decrypt(...params);
        };
      }

      it('should throw error if input is not a stream.Readable', () => {
        const options = {output: new PassThrough(), encryptionKey: encryptionKey, signatureKey: signatureKey};
        expect(callDecrypt(decrypter, options)).to.throw(TypeError, 'input must be a stream.Readable');
      });
      it('should throw error if output is not a stream.Writable', () => {
        const options = {input: new PassThrough(), encryptionKey: encryptionKey, signatureKey: signatureKey};
        expect(callDecrypt(decrypter, options)).to.throw(TypeError, 'output must be a stream.Writable');
      });
      it('should throw error if encryptionKey is not a buffer', () => {
        const options = {input: new PassThrough(), output: new PassThrough(), signatureKey: signatureKey};
        expect(callDecrypt(decrypter, options)).to.throw(TypeError, 'encryptionKey must be a Buffer');
      });
      it('should throw error if signatureKey is not a buffer', () => {
        const options = {input: new PassThrough(), output: new PassThrough(), encryptionKey: encryptionKey};
        expect(callDecrypt(decrypter, options)).to.throw(TypeError, 'signatureKey must be a Buffer');
      });
      it('should decrypt data', () => {
        const input = fs.createReadStream(INPUT_FILEPATH);
        const output = new PassThrough();
        const options = {input: input, output: output, encryptionKey: encryptionKey, signatureKey: signatureKey};
        return decrypter.decrypt(options);
      });
    });
  });
})();
