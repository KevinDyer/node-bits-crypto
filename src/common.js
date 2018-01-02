(() => {
  'use strict';

  const BLOCK_SIZE = 16;
  const KEY_LENGTH = 32;
  const IV_LENGTH = BLOCK_SIZE;
  const SALT_PREFIX = Buffer.from('Salted__');

  module.exports.BLOCK_SIZE = BLOCK_SIZE;
  module.exports.KEY_LENGTH = KEY_LENGTH;
  module.exports.IV_LENGTH = IV_LENGTH;
  module.exports.SALT_PREFIX = SALT_PREFIX;

  const fs = require('fs');
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
  module.exports.readFile = readFile;

  function unlink(path) {
    return new Promise((resolve, reject) => {
      fs.unlink(path, (err) => {
        if (err) {
          reject(err);
        } else {
          resolve();
        }
      });
    });
  }
  module.exports.unlink = unlink;

  function mkdtemp(prefix, options) {
    return new Promise((resolve, reject) => {
      fs.mkdtemp(prefix, options, (err, folder) => {
        if (err) {
          reject(err);
        } else {
          resolve(folder);
        }
      });
    });
  }
  module.exports.mkdtemp = mkdtemp;

  function rmdir(path) {
    return new Promise((resolve, reject) => {
      fs.rmdir(path, (err) => {
        if (err) {
          reject(err);
        } else {
          resolve();
        }
      });
    });
  }
  module.exports.rmdir = rmdir;

  function stat(path) {
    return new Promise((resolve, reject) => {
      fs.stat(path, (err, stats) => {
        if (err) {
          reject(err);
        } else {
          resolve(stats);
        }
      });
    });
  }
  module.exports.stat = stat;

  function readdir(path, options) {
    return new Promise((resolve, reject) => {
      fs.readdir(path, options, (err, files) => {
        if (err) {
          reject(err);
        } else {
          resolve(files);
        }
      });
    });
  }
  module.exports.readdir = readdir;

  function rmrdir(path) {
    return Promise.resolve()
      .then(() => readdir(path))
      .then((filenames) => {
        const filepaths = filenames.map((filename) => require('path').join(path, filename));
        return Promise.all(filepaths.map((filepath) => {
          return Promise.resolve()
            .then(() => stat(filepath))
            .then((stats) => {
              if (stats.isDirectory()) {
                return rmrdir(filepath);
              }
              return unlink(filepath);
            });
        }));
      })
      .then(() => rmdir(path));
  }
  module.exports.rmrdir = rmrdir;

  function rename(oldPath, newPath) {
    return new Promise((resolve, reject) => {
      fs.rename(oldPath, newPath, (err) => {
        if (err) {
          reject(err);
        } else {
          resolve();
        }
      });
    });
  }
  module.exports.rename = rename;

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
  module.exports.randomBytes = randomBytes;
})();
