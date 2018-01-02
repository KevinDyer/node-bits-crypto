(() => {
  'use strict';

  const path = require('path');
  const fs = require('fs');
  const {PassThrough} = require('stream');
  const Encrypter = require('./../src/encrypter');
  const Decrypter = require('./../src/decrypter');

  const TEST_PRIVATE_KEY_FILEPATH = path.join(__dirname, './fixtures/keys/test-key.pem');
  const TEST_PUBLIC_KEY_FILEPATH = path.join(__dirname, './fixtures/keys/test-key.pub');
  const SIGNATURE_PRIVATE_KEY_FILEPATH = path.join(__dirname, './fixtures/keys/signature-key.pem');
  const SIGNATURE_PUBLIC_KEY_FILEPATH = path.join(__dirname, './fixtures/keys/signature-key.pub');
  const INPUT_FILEPATH = path.join(__dirname, './fixtures/random-number-1.0.0.tgz');

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

    it('should encrypt and decrypt data', () => {
      const encryptOutput = new PassThrough();
      return Promise.resolve()
        .then(() => {
          const input = fs.createReadStream(INPUT_FILEPATH);
          const encrypter = new Encrypter({verbose: false});
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
          let buf = Buffer.alloc(0);
          function onData(data) {
            buf = Buffer.concat([buf, data], buf.length + data.length);
            if (buf.length < signature.length) {
              return;
            }
            encryptOutput.removeListener('data', onData);
            encryptOutput.unshift(buf.slice(signature.length));
            encryptOutput.pipe(input);
          }
          encryptOutput.on('data', onData);
          const decrypter = new Decrypter({verbose: false});
          const options = {
            input: input,
            output: fs.createWriteStream('/tmp/output.tgz'),
            encryptionKey: testPrivateKey,
            signatureKey: signaturePublicKey,
            signature: signature,
          };
          return decrypter.decrypt(options);
        });
    });
  });
})();
