#!/usr/bin/env node
(() => {
  'use strict';

  const path = require('path');
  const fs = require('fs');
  const stream = require('stream');
  const program = require('commander');
  const {version} = require('../package.json');
  const {Decrypter} = require('..');
  const {randomBytes, readFile, rename} = require('../src/common');

  function readDataFromReadable(readable, length) {
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

  function readHeader(input, options={}) {
    const response = {
      headerEnd: 0,
      headerLength: 0,
      header: null,
    };
    const {offset=-1} = options;
    if (0 < offset) {
      response.headerEnd = offset;
      response.headerLength = offset;
      return Promise.resolve()
        .then(() => readDataFromReadable(input, offset))
        .then((header) => {
          response.header = header;
          return response;
        });
    }
    return Promise.resolve()
      .then(() => readDataFromReadable(input, 24))
      .then((data) => {
        const index = data.indexOf('#');
        if (0 > index) {
          input.unshift(data);
          return response;
        }
        const headerLength = Number.parseFloat(data.slice(0, index).toString());
        if (!Number.isInteger(headerLength)) {
          input.unshift(data);
          return response;
        }
        const headerStart = index + 1;
        input.unshift(data.slice(headerStart));
        response.headerEnd = headerStart + headerLength;
        response.headerLength = headerLength;
        return readDataFromReadable(input, headerLength);
      })
      .then((header) => {
        response.header = header;
        return response;
      });
  }

  function parseAbsolutePath(val) {
    if (!path.isAbsolute(val)) {
      val = path.resolve(process.cwd(), val);
    }
    return val;
  }

  program
    .version(version)
    .option('-t, --target <target>', 'the encrypted file you want to decrypt', parseAbsolutePath)
    .option('-e, --encryption-key <encryptionKey>', 'the private key used to decrypt the file', parseAbsolutePath)
    .option('-s, --signing-key <signingKey>', 'the public key used to verify the signature', parseAbsolutePath)
    .option('-d, --output-directory [outputDirectory]', 'specify an alternate output directory for the encrypted file', parseAbsolutePath, process.cwd())
    .option('-n, --nofilename', 'do not include the filename in the package')
    .option('-o, --offset <offset>', 'Offset to start of data used if there is a header before the encryption this saves having to separate header and encrypted blob', parseInt)
    .option('-v, --verbose', 'verbose message printing')
    .parse(process.argv);

  if (!program.target) {
    console.error('must specify a target file to encrypt');
    process.exit(1);
    return;
  }

  if (!program.encryptionKey) {
    console.error('must specify an encryption key');
    process.exit(1);
    return;
  }

  if (!program.signingKey) {
    console.error('must specify an signing key');
    process.exit(1);
    return;
  }

  let decryptedFilepath = null;

  const input = fs.createReadStream(program.target);

  Promise.resolve()
    .then(() => randomBytes(3))
    .then((buf) => {
      const filename = `decrypted-${buf.toString('hex')}.file`;
      decryptedFilepath = path.join(program.outputDirectory, filename);
    })
    .then(() => Promise.all([
      readFile(program.encryptionKey),
      readFile(program.signingKey),
      readHeader(input, program),
    ]))
    .then(([encryptionKey, signatureKey, headerInfo]) => {
      const output = fs.createWriteStream(decryptedFilepath);
      const decrypter = new Decrypter({verbose: program.verbose, nofilename: program.nofilename});
      return decrypter.decrypt({
        input: input,
        output: output,
        encryptionKey: encryptionKey,
        signatureKey: signatureKey,
      });
    })
    .then(({filename}) => {
      if (program.nofilename) {
        return decryptedFilepath;
      }
      const outputFilepath = path.join(program.outputDirectory, filename);
      return Promise.resolve()
        .then(() => rename(decryptedFilepath, outputFilepath))
        .then(() => outputFilepath);
    })
    .then((filepath) => console.log(filepath))
    .catch((err) => console.error(err));
})();
