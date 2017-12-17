#!/usr/bin/python
# This python script decrypts data (*.mod) to a plaintext file.  The .enc file
# is an encrypted file that has been encrypted with a public key and signed with
# a private key
#
# The .enc file has the following format:
# +------------------------+
# +       signature        +
# +      [512 bytes]       +
# +------------------------+
# + RSA encrypted password +
# +      [512 bytes]       +
# +------------------------+
# +   RSA encrypted salt   +
# +      [512 bytes]       +
# +------------------------+
# + RSA encrypted filename +
# +      [512 bytes]       +
# +------------------------+
# +      Symmetric Key     +
# +    encrypted package   +
# +      [file.pack]     +
# +------------------------+

import sys, re, argparse, os, subprocess, shutil, struct, binascii
from os.path import basename
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from hashlib import md5
from json import loads


def read_header(in_filename):
    f = open(in_filename, 'r')
    tempStr = f.read(16) #header length should not be more than 16 bytes
    endIdx = tempStr.find('#')
    if endIdx > 0:
        headerLen = int(tempStr[0:endIdx])
        f.seek(endIdx + 1)
        header = loads(f.read(headerLen))
        header['offset'] = headerLen + endIdx + 1
        return header

def get_sha256(in_filename):
    CHUNK_SIZE = 16*1024
    file_sha256_checksum = SHA256.new()
    with open(in_filename, 'rb') as infile:
        while True:
            chunk = infile.read(CHUNK_SIZE)
            if len(chunk) == 0:
                break
            file_sha256_checksum.update(chunk)
        infile.close()
    return file_sha256_checksum

def find_keys(header, key_dir, settings):
    keyFiles = [os.path.join(key_dir, f) for f in os.listdir(key_dir) if os.path.isfile(os.path.join(key_dir, f))]
    publickeys = {}
    privatekeys = {}
    for keyFile in keyFiles:
        try:
            f = open(keyFile, 'r')
            rsakey = RSA.importKey(f.read())
            f.close()
            sha256 = get_sha256(keyFile)
            if rsakey.has_private():
                privatekeys[sha256.hexdigest()] = {'key': rsakey, 'filename': keyFile}
            else:
                publickeys[sha256.hexdigest()] = {'key': rsakey, 'filename': keyFile}
        except Exception:
            pass

    if not header.has_key('encKey') or not header.has_key('sigKey'):
        raise Exception("Invalid header does not have required key fields")

    if not publickeys.has_key(header['encKey']) or not privatekeys.has_key(header['sigKey']):
        raise Exception("Cannot find keys in key dir")

    for privatekey in privatekeys.values():
        if publickeys[header['encKey']]['key'].publickey() == privatekey['key'].publickey():
            settings.encryption_key = privatekey['filename']
            sys.stderr.write('Decryption key: %s\n' % (settings.encryption_key))

    for publickey in publickeys.values():
        if privatekeys[header['sigKey']]['key'].publickey() == publickey['key'].publickey():
            settings.signing_key = publickey['filename']
            sys.stderr.write('Signature key: %s\n' % (settings.signing_key))

    if settings.encryption_key == None or settings.signing_key == None:
        raise Exception("Cannot find complementary keys for decrypting")


# Derive a secret AES symmetric key from a password and salt
def derive_key_iv(password, salt):
    KEY_LENGTH = 32 #Indicates AES-256
    IV_LENGTH = AES.block_size
    if len(password) > 32:
        password = password[0:32]

    d = d_i = ''
    while len(d) < KEY_LENGTH + IV_LENGTH:
        d_i = md5(d_i + password + salt).digest()
        d += d_i
    return d[:KEY_LENGTH], d[KEY_LENGTH:KEY_LENGTH+IV_LENGTH]

# Decrypt a file to a plaintext file
# in_filename is the .enc/.mod file to decrypt
# file_offset optional offset of the start of the encrypted blob
# private_key is the RSA key to decrypt the AES key and Salt
# public_key is the signature RSA key to verify source
def decrypt_file(in_filename, file_offset, private_key, public_key, nofilename, outputdir, verbose):
    if verbose:
        print 'decrypting ' + in_filename
        print 'RSA key ' + private_key

    BLOCK_SIZE = AES.block_size
    MODE = AES.MODE_CBC
    CHUNK_SIZE = BLOCK_SIZE*1024

    f = open(private_key, 'r')
    privatersa_key = RSA.importKey(f.read())
    cipher = PKCS1_OAEP.new(privatersa_key)

    with open(in_filename, 'rb') as infile:
        infile.seek(file_offset)
        file_sha256_checksum = SHA256.new()

        signature_bin = infile.read(512)
        enc_pass = infile.read(512)
        enc_salt = infile.read(512)
        if not nofilename:
            enc_filename = infile.read(512)

        file_sha256_checksum.update(enc_pass)
        file_sha256_checksum.update(enc_salt)
        if not nofilename:
            file_sha256_checksum.update(enc_filename)

        while True:
            chunk = infile.read(CHUNK_SIZE)
            if len(chunk) == 0:
                break
            file_sha256_checksum.update(chunk)
        infile.close()

    sha256sum = file_sha256_checksum.hexdigest()
    if verbose:
        print 'sha256 sum of enc file ' + sha256sum

    f = open(public_key, 'r')
    publicrsa_key = RSA.importKey(f.read())

    if not verify_file_signature(file_sha256_checksum, signature_bin, publicrsa_key):
        print 'Signature verification failed'
        return False

    password = cipher.decrypt(enc_pass)
    salt_header = cipher.decrypt(enc_salt)
    salt = salt_header[len('Salted__'):]
    key, iv = derive_key_iv(password, salt)

    if outputdir == None:
        outputdir = os.path.dirname(in_filename)
    if not nofilename:
        try:
            filename = cipher.decrypt(enc_filename)
        except:
            print 'Error getting filename try with -n option'
            return False
        out_filename = os.path.join(outputdir, filename)
    if nofilename:
        out_filename = os.path.join(outputdir, os.path.splitext(os.path.basename())[0] + '.tgz')
    print out_filename

    with open(in_filename, 'rb') as infile:
        if not nofilename:
            infile.seek(2048 + file_offset)
        if nofilename:
            infile.seek(1536 + file_offset)
        decryptor = AES.new(key, MODE, iv)

        with open(out_filename, 'wb') as outfile:
            next_chunk = ''
            finished = False
            while not finished:
                chunk, next_chunk = next_chunk, decryptor.decrypt(infile.read(CHUNK_SIZE))
                if len(next_chunk) == 0:
                    padding_length = ord(chunk[-1])
                    chunk = chunk[:-padding_length]
                    finished = True
                outfile.write(chunk)
            outfile.close()
        infile.close()
    return True

def verify_file_signature(hash_value, signature_bin, publicrsa_key):
    verifier = PKCS1_v1_5.new(publicrsa_key)
    if verifier.verify(hash_value, signature_bin):
        return True
    else:
        return False

def __make_parser():
    p = argparse.ArgumentParser(description='This decrypts an encrypted file')
    p.add_argument('-t', '--encrypted-file', type=str, help='the encrypted file you want to decrypt', default=None, required = True)
    p.add_argument('-e', '--encryption-key', type=str, help='the private key used to decrypt the file', default=None, required = False)
    p.add_argument('-s', '--signing-key', type=str, help='the public key used to verify the signature', default=None, required = False)
    p.add_argument('-n', '--no-filename', action='store_true', help='do not include the filename in the package', default = False, required = False)
    p.add_argument('-v', '--verbose', action='store_true', help='verbose message printing', default = False, required = False)
    p.add_argument('-o', '--offset', type=int, help='Offset to start of data used if there is a header before the encryption this saves having to separate header and encrypted blob', required = False, default = 0)
    p.add_argument('-d', '--output-directory', type=str, help='specify an alternate output directory for the decrypted file', default = None, required = False)
    p.add_argument('-k', '--key-dir', type=str, help='specify directory for keys which will be determined from the header', default = None, required = False)
    return p

def __main(argv):
    parser = __make_parser()
    settings = parser.parse_args(argv[1:])
    MYDIR = os.path.dirname(os.path.realpath(__file__))

    if (not os.path.isfile(settings.encrypted_file)):
        sys.stderr.write('Error encrypted file is not a valid file\n')
        sys.exit(1)

    if settings.key_dir == None and (settings. encryption_key == None or settings.signing_key == None):
        devKeysDir = os.path.join(MYDIR, '..', 'keys')
        if not os.path.isdir(devKeysDir):
            sys.stderr.write('Must specify key dir or encryption key and signing key\n')
            sys.exit(1)
        settings.key_dir = devKeysDir

    settings.encrypted_file = os.path.abspath(settings.encrypted_file)

    if settings.key_dir:
        header = read_header(settings.encrypted_file)
        if header == None:
            sys.stderr.write('Cannot read encrypted file header\n')
            sys.exit(1)
        settings.offset = header['offset']
        find_keys(header, settings.key_dir, settings)


    if (settings.encryption_key != None):
        if settings.verbose:
            print "encryption key: " + settings.encryption_key
        if not decrypt_file(settings.encrypted_file, settings.offset, settings.encryption_key, settings.signing_key, settings.no_filename, settings.output_directory, settings.verbose):
            print 'Decryption failed'
            sys.exit(1)

    sys.exit(0)

if __name__ == "__main__":
    __main(sys.argv)

__doc__ += __make_parser().format_help()
