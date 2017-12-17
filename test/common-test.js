(() => {
  'use strict';

  const chai = require('chai');
  const {deriveKeyAndIV} = require('./../src/common');

  const expect = chai.expect;

  function callDeriveKeyAndIV(password, salt) {
    return function() {
      return deriveKeyAndIV(password, salt);
    };
  }

  describe('Common', () => {
    describe('deriveKeyAndIV', () => {
      it('should throw error if password is not a buffer', () => {
        expect(callDeriveKeyAndIV('not a password', Buffer.alloc(0))).to.throw(TypeError, 'password must be a buffer');
      });
      it('should throw error if salt is not a buffer', () => {
        expect(callDeriveKeyAndIV(Buffer.alloc(0), 'not a salt')).to.throw(TypeError, 'salt must be a buffer');
      });
      it.skip('should derive key and iv', () => {
        const {key, iv} = deriveKeyAndIV(Buffer.alloc(32), Buffer.alloc(8));
        console.log(require('util').inspect(key, {colors: true, depth: null}));
        console.log(require('util').inspect(iv, {colors: true, depth: null}));
      });
    });
  });
})();
