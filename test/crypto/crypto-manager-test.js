(() => {
  'use strict';

  const path = require('path');
  const fs = require('fs');
  const chai = require('chai');
  const {CryptoManager} = require('../..');
  const expect = chai.expect;

  const FILEPATH_PRIVATE_KEY = path.resolve(__dirname, './../fixtures/test-key.pem');
  const FILEPATH_PUBLIC_KEY = path.resolve(__dirname, './../fixtures/test-key.pub');
  const FILEPATH_TXT = path.resolve(__dirname, './../fixtures/test.txt');

  describe('crypto', () => {
    describe('CryptoManager', () => {
      let privateKey = null;
      before('Read private key', (done) => {
        fs.readFile(FILEPATH_PRIVATE_KEY, 'utf8', (err, data) => {
          privateKey = data;
          done(err);
        });
      });
      let publicKey = null;
      before('Read public key', (done) => {
        fs.readFile(FILEPATH_PUBLIC_KEY, 'utf8', (err, data) => {
          publicKey = data;
          done(err);
        });
      });
      
      describe('sign', () => {
        it('should return a Promise', () => {
          const manager = new CryptoManager();
          expect(manager.sign({algorithm: 'sha256', data: Buffer.alloc(0), privateKey: privateKey})).to.be.instanceof(Promise);
        });
        
        it('should calculate a signature', () => {
          const manager = new CryptoManager();
          return Promise.resolve()
            .then(() => manager.sign({
              algorithm: 'sha256',
              privateKey: privateKey,
              data: fs.createReadStream(FILEPATH_TXT),
              outputFormat: 'hex'
            }))
            .then((signature) => manager.verify({
              algorithm: 'sha256',
              publicKey: publicKey,
              data: fs.createReadStream(FILEPATH_TXT),
              signature: signature,
              signatureFormat: 'hex',
            }))
            .then((verified) => expect(verified).to.be.true);
        });
      });
    });
  });
})();
