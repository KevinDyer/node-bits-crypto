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
  // +      [file.pack]       +
  // +------------------------+

  const stream = require('stream');
  const crypto = require('crypto');
  const {deriveKeyAndIV, SALT_PREFIX} = require('./common');
  const {NiceWriter} = require('./nice-writer');

  class Decrypter {
    constructor({verbose=false, nofilename=false}={}) {
      this._verbose = (true === verbose);
      this._includeFilename = (true !== nofilename);
    }

    _debug(...params) {
      if (this._verbose) {
        console.log(...params);
      }
    }

    decrypt({input, output, encryptionKey, signatureKey}) {
      if (!(input instanceof stream.Readable)) {
        throw new TypeError('input must be a stream.Readable');
      }
      if (!(output instanceof stream.Writable)) {
        throw new TypeError('output must be a stream.Writable');
      }
      if (!Buffer.isBuffer(encryptionKey)) {
        throw new TypeError('encryptionKey must be a Buffer');
      }
      if (!Buffer.isBuffer(signatureKey)) {
        throw new TypeError('signatureKey must be a Buffer');
      }
      const verifier = crypto.createVerify('sha256');
      const verifierWriter = new NiceWriter(verifier);
      const holder = {};
      return Promise.resolve()
        .then(() => this._readDataFromReadable(input, 512))
        .then((signature) => {
          holder.signature = signature;
        })
        .then(() => this._readDataFromReadable(input, 512))
        .then((encryptedPassword) => {
          verifierWriter.write(encryptedPassword);
          const password = crypto.privateDecrypt(encryptionKey, encryptedPassword);
          holder.password = password;
        })
        .then(() => this._readDataFromReadable(input, 512))
        .then((encryptedSalt) => {
          verifierWriter.write(encryptedSalt);
          const salt = crypto.privateDecrypt(encryptionKey, encryptedSalt);
          const saltSuffix = salt.slice(SALT_PREFIX.length);
          holder.saltSuffix = saltSuffix;
          const {iv, key} = deriveKeyAndIV(holder.password, holder.saltSuffix);
          holder.iv = iv;
          holder.key = key;
        })
        .then(() => {
          if (this._includeFilename) {
            return Promise.resolve()
              .then(() => this._readDataFromReadable(input, 512))
              .then((encryptedFilename) => {
                verifierWriter.write(encryptedFilename);
                const filename = crypto.privateDecrypt(encryptionKey, encryptedFilename);
                holder.filename = filename.toString();
              });
          }
        })
        .then(() => {
          const {password, saltSuffix, iv, key, filename} = holder;
          this._debug(`Random Password:     %s`, password.toString('hex'));
          this._debug(`Random Salt(suffix): %s`, saltSuffix.toString('hex'));
          this._debug(`IV:                  %s`, iv.toString('hex'));
          this._debug(`KEY:                 %s`, key.toString('hex'));
          if (this._includeFilename) {
            this._debug(`Filename:            %s`, filename);
          }
          input.on('data', (data) => {
            verifierWriter.write(data);
          });
          input.once('end', () => {
            verifierWriter.end();
          });
          const outputWriter = new NiceWriter(output);
          const decipher = crypto.createDecipheriv('AES-256-CBC', key, iv);
          decipher.on('data', (data) => outputWriter.write(data));
          decipher.once('end', () => outputWriter.end());
          input.pipe(decipher);
          input.resume();
          return this._waitUntilWritablesFinish([verifier, output]);
        })
        .then(() => {
          const verified = verifier.verify(signatureKey, holder.signature);
          if (!verified) {
            return Promise.reject(new Error('signature check failed'));
          }
          return {filename: holder.filename};
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

    _readDataFromReadable(readable, length) {
      if (!(readable instanceof stream.Readable)) {
        throw new TypeError('readable must be a stream.Readable');
      }
      return new Promise((resolve, reject) => {
        function onError(err) {
          readable.removeListener('data', onData);
          readable.removeListener('end', onEnd);
          reject(err);
        }
        let data = Buffer.alloc(0);
        function onData(chunk) {
          data = Buffer.concat([data, chunk], data.length + chunk.length);
          if (data.length < length) {
            return;
          }
          readable.pause();
          readable.unshift(data.slice(length));
          readable.removeListener('error', onError);
          readable.removeListener('data', onData);
          readable.removeListener('end', onEnd);
          resolve(data.slice(0, length));
        }
        function onEnd() {
          readable.removeListener('error', onError);
          readable.removeListener('data', onData);
          reject(new Error('readable ended before data could be read'));
        }
        readable.once('error', onError);
        readable.on('data', onData);
        readable.once('end', onEnd);
        readable.resume();
      });
    }
  }

  module.exports = Decrypter;
})();
