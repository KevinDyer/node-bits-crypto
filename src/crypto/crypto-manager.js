(() => {
  'use strict';

  const crypto = require('crypto');
  const stream = require('stream');

  class CryptoManager {
    sign({algorithm, data, privateKey, outputFormat}={}) {
      return new Promise((resolve, reject) => {
        const sign = crypto.createSign(algorithm);
        sign.once('error', reject);
        sign.on('finish', () => {
          const signature = sign.sign(privateKey, outputFormat);
          resolve(signature);
        });
        if (data instanceof stream.Readable) {
          data.pipe(sign);
        } else {
          sign.write(data);
          sign.end();
        }
      });
    }

    verify({algorithm, data, publicKey, signature, signatureFormat}={}) {
      return new Promise((resolve, reject) => {
        const verify = crypto.createVerify(algorithm);
        verify.once('error', reject);
        verify.on('finish', () => {
          const verified = verify.verify(publicKey, signature, signatureFormat);
          resolve(verified);
        });
        if (data instanceof stream.Readable) {
          data.pipe(verify);
        } else {
          verify.write(data);
          verify.end();
        }
      });
    }
  }

  module.exports = CryptoManager;
})();
