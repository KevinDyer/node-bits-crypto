#!/usr/bin/env node
(() => {
  'use strict';

  const path = require('path');
  const fs = require('fs');
  const crypto = require('crypto');
  const program = require('commander');
  const {version} = require('../package.json');
  const {Encrypter} = require('..');

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

  function getHeader(options={}) {
    const {addKeyHeader=false, addFileHeader=null} = options;
    if (addKeyHeader) {
      const {encryptionKey, signingKey} = options;
      const encryptionKeyHash = crypto.createHash('sha256').update(encryptionKey).digest('hex');
      const signingKeyHash = crypto.createHash('sha256').update(signingKey).digest('hex');
      const header = {encKey: encryptionKeyHash, sigKey: signingKeyHash};
      return Promise.resolve(Buffer.from(JSON.stringify(header)));
    }
    if (null !== addFileHeader) {
      return Promise.resolve()
        .then(() => readFile(addFileHeader));
    }
    return Promise.resolve(Buffer.alloc(0));
  }

  function parseAbsolutePath(val) {
    if (!path.isAbsolute(val)) {
      val = path.resolve(process.cwd(), val);
    }
    return val;
  }

  program
    .version(version)
    .option('-t, --target <target>', 'path to the file that you would like encrypted', parseAbsolutePath)
    .option('-e, --encryption-key <encryptionKey>', 'the public key used to encrypt the data', parseAbsolutePath)
    .option('-s, --signing-key <signingKey>', 'the private key used to sign the data', parseAbsolutePath)
    .option('-d, --output-directory [outputDirectory]', 'specify an alternate output directory for the encrypted file', parseAbsolutePath, process.cwd())
    .option('-m, --module', 'this is a module')
    .option('-n, --nofilename', 'do not include the filename in the package')
    .option('-a, --add-key-header', 'add a JSON header indicating the keys used to encrypt')
    .option('-H, --add-file-header [fileHeader]', 'add the specified header file', parseAbsolutePath)
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

  let outputExt = '.enc';
  if (program.module) {
    outputExt = '.mod';
  }

  const extname = path.extname(program.target);
  const filenameWithExt = path.basename(program.target);
  const filename = path.basename(filenameWithExt, extname);
  const filepath = path.join(program.outputDirectory, `${filename}${outputExt}`);
  let headerEnd = 0;

  Promise.resolve()
    .then(() => Promise.all([
      readFile(program.encryptionKey),
      readFile(program.signingKey),
    ]))
    .then(([encryptionKey, signatureKey]) => {
      return Promise.all([
        encryptionKey,
        signatureKey,
        getHeader(Object.assign(program, {encryptionKey: encryptionKey, signingKey: signatureKey})),
      ]);
    })
    .then(([encryptionKey, signatureKey, header]) => {
      const output = fs.createWriteStream(filepath);

      if (Buffer.isBuffer(header) && 0 < header.length) {
        const headerPrefix = `${header.length}#`;
        headerEnd = Buffer.byteLength(headerPrefix) + header.length;
        output.write(headerPrefix);
        output.write(header);
      }

      const input = fs.createReadStream(program.target);
      const encrypter = new Encrypter({verbose: program.verbose, nofilename: program.nofilename});
      return encrypter.encrypt({
        input: input,
        output: output,
        encryptionKey: encryptionKey,
        signatureKey: signatureKey,
        filename: filenameWithExt,
      });
    })
    .then((signature) => {
      return new Promise((resolve, reject) => {
        const output = fs.createWriteStream(filepath, {start: headerEnd, flags: 'r+'});
        output.once('error', reject);
        output.once('finish', resolve);
        output.write(signature);
        output.end();
      });
    })
    .then(() => console.log(filepath))
    .catch((err) => console.error(err));
})();
