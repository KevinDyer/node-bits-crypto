(() => {
  'use strict';

  const stream = require('stream');

  class NiceWriter {
    constructor(writable) {
      if (!(writable instanceof stream.Writable)) {
        throw new TypeError('writable must be a stream.Writable');
      }
      this._writable = writable;
      this._chain = Promise.resolve();
    }

    write(chunk, encoding, callback) {
      this._chain = this._chain
        .then(() => this._write(chunk, encoding, callback));
      return this._chain;
    }

    _write(chunk, encoding, callback) {
      return new Promise((resolve, reject) => {
        if (this._writable.write(chunk, encoding, callback)) {
          process.nextTick(() => resolve(true));
        } else {
          this._writable.once('error', reject);
          this._writable.once('drain', () => {
            this._writable.removeListener('error', reject);
            resolve(false);
          });
        }
      });
    }

    end(chunk, encoding, callback) {
      this._chain = this._chain
        .then(() => this._end(chunk, encoding, callback));
      return this._chain;
    }

    _end(chunk, encoding, callback) {
      return new Promise((resolve, reject) => {
        this._writable.once('error', reject);
        this._writable.once('finish', resolve);
        this._writable.end(chunk, encoding, callback);
      });
    }
  }

  module.exports.NiceWriter = NiceWriter;
})();
