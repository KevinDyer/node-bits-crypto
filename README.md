# node-bits-crypto
This is a node module implementation of BITS encrypt/decrypt.

### Install
``` bash
npm install @skidder/bits-crypto
```

### Encrypt data
``` javascript
const {Encrypter} = require('@skidder/bits-crypto');

const encryptionKey = getPublicEncryptionKey();
const signatureKey = getPrivateSignatureKey();

const encrypter = new Encrypter();
Promise.resolve()
  .then(() => encrypter.encrypt({
    input: fs.createReadStream('data.txt'),
    output: fs.createWriteStream('data.txt.enc'),
    encryptionKey: encryptionKey,
    signatureKey: signatureKey,
    filename: 'data.txt',
  })
  .then((signature) => {
    const output = fs.createWriteStream('data.txt.enc', {start: 0, end: 512, flags: 'r+'})
    output.write(signature);
    output.end();
  });
```

### Decrypt data
``` javascript
const {Decrypter} = require('@skidder/bits-crypto');

const encryptionKey = getPrivateEncryptionKey();
const signatureKey = getPublicSignatureKey();

const decrypter = new Decrypter();
Promise.resolve()
  .then(() => decrypter.decrypt({
    input: fs.createReadStream('data.txt.enc'),
    output: fs.createWriteStream('data.txt'),
    encryptionKey: encryptionKey,
    signatureKey: signatureKey,
  });
```

### CLI
This module also provides two scripts to encrypt and decrypt data from the command line. See the help for command details.
``` bash
npm install -g @skidder/bits-crypto
encrypt-data -t data.txt -e foo-key.pub -s mine-key.pem
decrypt-data -t data.enc -e foo-key.pem -s mine-key.pub
```