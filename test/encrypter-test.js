(() => {
  'use strict';

  const path = require('path');
  const fs = require('fs');
  const chai = require('chai');
  const {PassThrough} = require('stream');
  const Encrypter = require('./../src/encrypter');
  const {BLOCK_SIZE} = require('./../src/common');

  const ENCRYPTION_KEY_FILEPATH = path.join(__dirname, './fixtures/keys/test-key.pub');
  const SIGNATURE_KEY_FILEPATH = path.join(__dirname, './fixtures/keys/signature-key.pem');
  const INPUT_FILEPATH = path.join(__dirname, './fixtures/random-number-1.0.0.tgz');

  const expect = chai.expect;

  describe('Encrypter', () => {
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

    describe('encrypter', () => {
      let encrypter = null;
      beforeEach('Create encrypter', () => {
        encrypter = new Encrypter();
      });

      function callEncrypt(encrypter, ...params) {
        return function encrypt() {
          encrypter.encrypt(...params);
        };
      }

      it('should throw error if input is not a stream.Readable', () => {
        const options = {output: new PassThrough(), encryptionKey: encryptionKey, signatureKey: signatureKey, filename: 'test.enc'};
        expect(callEncrypt(encrypter, options)).to.throw(TypeError, 'input must be a stream.Readable');
      });
      it('should throw error if output is not a stream.Writable', () => {
        const options = {input: new PassThrough(), encryptionKey: encryptionKey, signatureKey: signatureKey, filename: 'test.enc'};
        expect(callEncrypt(encrypter, options)).to.throw(TypeError, 'output must be a stream.Writable');
      });
      it('should throw error if filename is a non-empty string', () => {
        const options = {input: new PassThrough(), output: new PassThrough(), encryptionKey: encryptionKey, signatureKey: signatureKey};
        expect(callEncrypt(encrypter, options)).to.throw(TypeError, 'filename must be a non-empty string');
      });
      it('should not throw error if filename is a non-empty string and nofilename is true', () => {
        const encrypter = new Encrypter({nofilename: true});
        const options = {input: new PassThrough(), output: new PassThrough(), encryptionKey: encryptionKey, signatureKey: signatureKey};
        expect(callEncrypt(encrypter, options)).to.not.throw();
      });
      it('should throw error if encryptionKey is not a buffer', () => {
        const options = {input: new PassThrough(), output: new PassThrough(), signatureKey: signatureKey, filename: 'test.enc'};
        expect(callEncrypt(encrypter, options)).to.throw(TypeError, 'encryptionKey must be a Buffer');
      });
      it('should throw error if signatureKey is not a buffer', () => {
        const options = {input: new PassThrough(), output: new PassThrough(), encryptionKey: encryptionKey, filename: 'test.enc'};
        expect(callEncrypt(encrypter, options)).to.throw(TypeError, 'signatureKey must be a Buffer');
      });
      it('should encrypt data', () => {
        const encrypter = new Encrypter();
        const input = fs.createReadStream(INPUT_FILEPATH);
        const output = new class extends PassThrough {
          constructor() {
            super();
            this.length = 0;
          }
          write(chunk, encoding, callback) {
            this.length += chunk.length;
            return super.write(chunk, encoding, callback);
          }
        };
        const options = {input: input, output: output, encryptionKey: encryptionKey, signatureKey: signatureKey, filename: 'test.enc'};
        return Promise.resolve()
        .then(() => encrypter.encrypt(options))
        .then((signature) => {
          const bytesRead = input.bytesRead + (BLOCK_SIZE - (input.bytesRead % BLOCK_SIZE));
          expect(output.length).to.equal(512 + 512 + 512 + 512 + bytesRead);
        });
      });
    });
  });
})();
