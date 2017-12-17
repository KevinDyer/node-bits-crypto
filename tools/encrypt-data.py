#!/usr/bin/python
# This python script encrypts any file as a .enc.  The .enc file is
# an encrypted file that is signed with a signing private key.
# You will have to install the python-crypto package if it is not already installed.
# Useful resources:
# https://www.dlitz.net/software/pycrypto/api/current/Crypto.Signature.PKCS1_v1_5-module.html
# https://www.dlitz.net/software/pycrypto/api/current/Crypto.PublicKey.RSA._RSAobj-class.html#sign
# https://www.dlitz.net/software/pycrypto/api/current/Crypto.Cipher.PKCS1_OAEP-module.html
# http://www.laurentluce.com/posts/python-and-cryptography-with-pycrypto/
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
# +       [file.pack]      +
# +------------------------+

import sys, re, argparse, os, subprocess, tempfile, shutil, fnmatch, base64, struct, string, random, binascii
from os.path import basename
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from hashlib import md5
from json import dumps

SIGNATURE_LEN = 512

def random_password_generator(length):
    return ''.join([random.choice(string.printable) for n in xrange(length)]).replace('\n', '')

def derive_key_iv(password, salt):
    KEY_LENGTH = 32
    IV_LENGTH = AES.block_size
    if len(password) > 32:
        password = password[0:32]

    d = d_i = ''
    while len(d) < KEY_LENGTH + IV_LENGTH:
        d_i = md5(d_i + password + salt).digest()
        d += d_i
    return d[:KEY_LENGTH], d[KEY_LENGTH:KEY_LENGTH+IV_LENGTH]

def encrypt_file(in_filename, public_key, nofilename, outputdir, verbose):
    if verbose:
        print 'encrypting ' + in_filename
        print 'RSA key ' + public_key

    BLOCK_SIZE = AES.block_size
    KEY_SIZE = 32
    MODE = AES.MODE_CBC
    CHUNK_SIZE = BLOCK_SIZE*1024 #CHUNK_SIZE is the size to read in bytes

    password = random_password_generator(32)
    if verbose:
        print 'Random Password (hexlify ASCII binary) ' + binascii.hexlify(password)
    salt = Random.new().read(BLOCK_SIZE - len('Salted__'))
    if verbose:
        print 'Random Salt (hexlify ASCII binary)' + binascii.hexlify(salt)

    key, IV = derive_key_iv(password, salt)
    if verbose:
        print 'IV: ' + binascii.hexlify(IV)
        print 'KEY: ' + binascii.hexlify(key)

    f = open(public_key, 'r')
    publicrsa_key = RSA.importKey(f.read())
    cipher = PKCS1_OAEP.new(publicrsa_key)

    enc_pass = cipher.encrypt(password)
    enc_salt = cipher.encrypt('Salted__' + salt)
    enc_filename = cipher.encrypt(os.path.basename(in_filename))

    encryptor = AES.new(key, MODE, IV)
    filesize = os.path.getsize(in_filename)

    #out_filename = os.path.splitext(in_filename)[0] + '.pack'
    if outputdir == None:
        outputdir = os.path.dirname(in_filename)
    out_filename = os.path.join(outputdir, os.path.splitext(os.path.basename(in_filename))[0] + '.pack')

    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(enc_pass)
            outfile.write(enc_salt)
            if not nofilename:
                outfile.write(enc_filename)

            finished = False
            while not finished:
                chunk = infile.read(CHUNK_SIZE)
                if len(chunk) == 0 or len(chunk) % BLOCK_SIZE != 0:
                    padding_length = (BLOCK_SIZE - len(chunk) % BLOCK_SIZE) or BLOCK_SIZE
                    chunk += padding_length * chr(padding_length)
                    finished = True
                outfile.write(encryptor.encrypt(chunk))
            outfile.close()
        infile.close()

    return out_filename

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

def sign_module(in_filename, public_key, private_key, extension, outputdir, addkeyheader, verbose, fileHeader=None):
    CHUNK_SIZE = 16*1024
    if verbose:
        print 'signing ' + in_filename
        print 'RSA key ' + private_key
        print '{} {}'.format('encrypted file size', os.path.getsize(in_filename))
        print 'extension ' + extension

    f = open(private_key, 'r')
    privatersa_key = RSA.importKey(f.read())
    f.close()

    file_sha256_checksum = get_sha256(in_filename)
    sha256sum = file_sha256_checksum.hexdigest()
    if verbose:
        print 'sha256 sum of enc file ' + sha256sum

    signer = PKCS1_v1_5.new(privatersa_key)
    signature = signer.sign(file_sha256_checksum)

    if outputdir == None:
        outputdir = os.path.dirname(in_filename)
    out_filename = os.path.join(outputdir, os.path.splitext(os.path.basename(in_filename))[0] + extension)
    print out_filename

    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            if addkeyheader:
                privatersa_sha256 = get_sha256(private_key)
                publicrsa_sha256 = get_sha256(public_key)
                headerStr = dumps({'encKey': publicrsa_sha256.hexdigest(), 'sigKey': privatersa_sha256.hexdigest()}).rstrip('\n')
                headerStr = str(len(headerStr)) + '#' + headerStr
                outfile.write(headerStr)
            elif fileHeader:
                with open(fileHeader, 'r') as fh:
                    headerStr = fh.read()
                    outfile.write(headerStr)
            outfile.write(signature)

            while True:
                chunk = infile.read(CHUNK_SIZE)
                if len(chunk) == 0:
                    break
                outfile.write(chunk)
            outfile.close()
        infile.close()

    os.remove(in_filename)

def __make_parser():
    p = argparse.ArgumentParser(description='This packages any file into an encrypted enc file')
    p.add_argument('-t', '--target', type=str, help='path to the file that you would like encrypted', required = True)
    p.add_argument('-e', '--encryptionkey', type=str, help='the public key used to encrypt the module', default=None, required = False)
    p.add_argument('-s', '--signingkey', type=str, help='the private key used to sign the module', default=None, required = False)
    p.add_argument('-m', '--module', action='store_true', help='this is a module', required = False)
    p.add_argument('-n', '--nofilename', action='store_true', help='do not include the filename in the package', default = False, required = False)
    p.add_argument('-v', '--verbose', action='store_true', help='verbose message printing', default = False, required = False)
    p.add_argument('-d', '--output-directory', type=str, help='specify an alternate output directory for the encrypted file', default = None, required = False)
    p.add_argument('-a', '--add-key-header', action='store_true', help='add a json header indicating the keys used to encrypt', default = False, required = False)
    p.add_argument('-H', '--add-file-header', type=str, help='add a json header the specified file', default = None, required = False)
    return p

def __main(argv):
    parser = __make_parser()
    settings = parser.parse_args(argv[1:])
    MYDIR = os.path.dirname(os.path.realpath(__file__))

    if (not os.path.isfile(settings.target)):
        sys.stderr.write('Error file you supplied is invalid\n')
        sys.exit(1)

    settings.target = os.path.abspath(settings.target)

    filename = settings.target

    if (settings.encryptionkey != None):
        enc_filename = encrypt_file(filename, settings.encryptionkey, settings.nofilename, settings.output_directory, settings.verbose)

    if settings.module:
        extension = '.mod'
    if not settings.module:
        extension = '.enc'

    if (settings.signingkey != None):
        sign_module(enc_filename, settings.encryptionkey, settings.signingkey, extension, settings.output_directory, settings.add_key_header, settings.verbose, settings.add_file_header)

    sys.exit(0)

if __name__ == "__main__":
    __main(sys.argv)

__doc__ += __make_parser().format_help()
