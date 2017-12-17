(() => {
  'use strict';

  // The .enc file has the following format:
  // +------------------------+
  // +       signature        +
  // +      [512 bytes]       +
  // +------------------------+
  // + RSA encrypted password +
  // +      [512 bytes]       +
  // +------------------------+
  // +   RSA encrypted salt   +
  // +      [512 bytes]       +
  // +------------------------+
  // + RSA encrypted filename +
  // +      [512 bytes]       +
  // +------------------------+
  // +      Symmetric Key     +
  // +    encrypted package   +
  // +       [file.pack]      +
  // +------------------------+

  const stream = require('stream');
  const crypto = require('crypto');
  const {deriveKeyAndIV, isNonEmptyString, BLOCK_SIZE, SALT_PREFIX} = require('./common');
  const {NiceWriter} = require('./nice-writer');

  function randomBytes(size) {
    return new Promise((resolve, reject) => {
      crypto.randomBytes(size, (err, buf) => {
        if (err) {
          reject(err);
        } else {
          resolve(buf);
        }
      });
    });
  }

  class Encrypter {
    constructor({verbose=false, nofilename=false}={}) {
      this._verbose = (true === verbose);
      this._includeFilename = (true !== nofilename);
    }

    _debug(...params) {
      if (this._verbose) {
        console.log(...params);
      }
    }

    encrypt({input, output, encryptionKey, signatureKey, filename}) {
      if (!(input instanceof stream.Readable)) {
        throw new TypeError('input must be a stream.Readable');
      }
      if (!(output instanceof stream.Writable)) {
        throw new TypeError('output must be a stream.Writable');
      }
      const outputWriter = new NiceWriter(output);
      if (this._includeFilename && !isNonEmptyString(filename)) {
        throw new TypeError('filename must be a non-empty string');
      }
      if (!Buffer.isBuffer(encryptionKey)) {
        throw new TypeError('encryptionKey must be a Buffer');
      }
      if (!Buffer.isBuffer(signatureKey)) {
        throw new TypeError('signatureKey must be a Buffer');
      }
      const signer = crypto.createSign('sha256');
      const signerWriter = new NiceWriter(signer);
      return Promise.resolve()
      .then(() => this._createPasswordSaltKeyAndIV())
      .then(({password, salt, iv, key}) => {
        outputWriter.write(Buffer.alloc(512));
        const encryptedPassword = crypto.publicEncrypt(encryptionKey, password);
        outputWriter.write(encryptedPassword);
        signerWriter.write(encryptedPassword);
        const encryptedSalt = crypto.publicEncrypt(encryptionKey, salt);
        outputWriter.write(encryptedSalt);
        signerWriter.write(encryptedSalt);
        if (this._includeFilename) {
          const encryptedFilename = crypto.publicEncrypt(encryptionKey, password);
          outputWriter.write(encryptedFilename);
          signerWriter.write(encryptedFilename);
        }
        const cipher = crypto.createCipheriv('AES-256-CBC', key, iv);
        cipher.on('data', (data) => {
          outputWriter.write(data);
          signerWriter.write(data);
        });
        cipher.on('end', () => {
          outputWriter.end();
          signerWriter.end();
        });
        input.pipe(cipher);
        return this._waitUntilWritablesFinish([output, signer]);
      })
      .then(() => {
        const signature = signer.sign(signatureKey);
        return signature;
      });
    }

    _waitUntilWritablesFinish(writables) {
      if (!Array.isArray(writables)) {
        writables = [writables];
      }
      if (writables.some((writable) => !(writable instanceof stream.Writable))) {
        throw new TypeError('writables must be an array of stream.Writables');
      }
      return Promise.all(writables.map((writable) => {
        return new Promise((resolve, reject) => {
          writable.once('error', reject);
          writable.once('finish', resolve);
        });
      }));
    }

    _createPasswordSaltKeyAndIV() {
      return Promise.resolve()
      .then(() => Promise.all([this._createPassword(), this._createSaltSuffix()]))
      .then(([password, saltSuffix]) => {
        const {iv, key} = deriveKeyAndIV(password, saltSuffix);
        const salt = Buffer.concat([SALT_PREFIX, saltSuffix], SALT_PREFIX.length + saltSuffix.length);
        this._debug(`Random Password:     %s`, password.toString('hex'));
        this._debug(`Random Salt(suffix): %s`, saltSuffix.toString('hex'));
        this._debug(`IV:                  %s`, iv.toString('hex'));
        this._debug(`KEY:                 %s`, key.toString('hex'));
        return {password: password, salt: salt, iv: iv, key: key};
      });
    }

    _createPassword() {
      return randomBytes(32);
    }

    _createSaltSuffix() {
      return randomBytes(BLOCK_SIZE - SALT_PREFIX.length);
    }
  }

  module.exports = Encrypter;
})();
