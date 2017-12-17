(() => {
  'use strict';

  const BLOCK_SIZE = 16;
  const KEY_LENGTH = 32;
  const IV_LENGTH = BLOCK_SIZE;
  const SALT_PREFIX = Buffer.from('Salted__');

  const crypto = require('crypto');

  function deriveKeyAndIV(password, salt) {
    if (!Buffer.isBuffer(password)) {
      throw new TypeError('password must be a buffer');
    }
    if (!Buffer.isBuffer(salt)) {
      throw new TypeError('salt must be a buffer');
    }
    if (KEY_LENGTH < password.length) {
      password = password.slice(0, KEY_LENGTH);
    }
    let d = Buffer.alloc(0);
    let dI = Buffer.alloc(0);
    while (KEY_LENGTH + IV_LENGTH > d.length) {
      const hash = crypto.createHash('md5');
      dI = hash.update(Buffer.concat([dI, password, salt], dI.length + password.length + salt.length)).digest();
      d = Buffer.concat([d, dI], d.length + dI.length);
    }
    const key = d.slice(0, KEY_LENGTH);
    const iv = d.slice(KEY_LENGTH, KEY_LENGTH + IV_LENGTH);
    return {key: key, iv: iv};
  }
  module.exports.deriveKeyAndIV = deriveKeyAndIV;

  function isNonEmptyString(str) {
    return 'string' === typeof(str) && 0 < str.length;
  }
  module.exports.isNonEmptyString = isNonEmptyString;

  module.exports.BLOCK_SIZE = BLOCK_SIZE;
  module.exports.KEY_LENGTH = KEY_LENGTH;
  module.exports.IV_LENGTH = IV_LENGTH;
  module.exports.SALT_PREFIX = SALT_PREFIX;
})();
