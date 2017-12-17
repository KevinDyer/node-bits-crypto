(() => {
  'use strict';

  const path = require('path');
  const fs = require('fs');
  const chai = require('chai');
  const {PassThrough} = require('stream');
  const Encrypter = require('./../src/encrypter');
  const Decrypter = require('./../src/decrypter');

  const TEST_PRIVATE_KEY_FILEPATH = path.join(__dirname, './fixtures/keys/test-key.pem');
  const TEST_PUBLIC_KEY_FILEPATH = path.join(__dirname, './fixtures/keys/test-key.pub');
  const SIGNATURE_PRIVATE_KEY_FILEPATH = path.join(__dirname, './fixtures/keys/signature-key.pem');
  const SIGNATURE_PUBLIC_KEY_FILEPATH = path.join(__dirname, './fixtures/keys/signature-key.pub');

  const expect = chai.expect;

  function readFile(file, options) {
    return new Promise((resolve, reject) => {
      fs.readFile(file, options, (err, data) => {
        if (err) {
          reject(err);
        } else {
          resolve(data);
        }
      });
    });
  }

  describe('Throughput', () => {
    let testPrivateKey = null;
    before('Read encryption key', () => {
      return readFile(TEST_PRIVATE_KEY_FILEPATH)
      .then((data) => {
        testPrivateKey = data;
      });
    });

    let testPublicKey = null;
    before('Read encryption key', () => {
      return readFile(TEST_PUBLIC_KEY_FILEPATH)
      .then((data) => {
        testPublicKey = data;
      });
    });

    let signaturePrivateKey = null;
    before('Read encryption key', () => {
      return readFile(SIGNATURE_PRIVATE_KEY_FILEPATH)
      .then((data) => {
        signaturePrivateKey = data;
      });
    });

    let signaturePublicKey = null;
    before('Read encryption key', () => {
      return readFile(SIGNATURE_PUBLIC_KEY_FILEPATH)
      .then((data) => {
        signaturePublicKey = data;
      });
    });

    it.skip('should encrypt and decrypt data', () => {
      const encryptOutput = new PassThrough();
      const decryptOutput = new PassThrough();
      return Promise.resolve()
      .then(() => {
        const input = new PassThrough();
        input.end(Buffer.from('foo'));
        const encrypter = new Encrypter();
        const options = {
          input: input,
          output: encryptOutput,
          encryptionKey: testPublicKey,
          signatureKey: signaturePrivateKey,
          filename: 'test.enc',
        };
        return encrypter.encrypt(options);
      })
      .then((signature) => {
        const input = new PassThrough();
        input.write(signature);
        encryptOutput.pipe(input);
        const decrypter = new Decrypter();
        const options = {
          input: input,
          output: decryptOutput,
          encryptionKey: testPrivateKey,
          signatureKey: signaturePublicKey,
        };
        return decrypter.decrypt(options);
      })
      .then(() => {
        return new Promise((resolve, reject) => {
          decryptOutput.once('error', reject);
          let data = Buffer.alloc(0);
          decryptOutput.on('data', (chunk) => {
            data = Buffer.concat([data, chunk], data.length + chunk.length);
          });
          decryptOutput.once('end', () => resolve(data));
        });
      })
      .then((data) => {
        expect(data.toString()).to.equal('foo');
      });
    });
  });
})();
