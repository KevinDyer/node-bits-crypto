# node-bits-crypto

``` bash
openssl genrsa -out signature-key.pem 4096
openssl rsa -in signature-key.pem -pubout -out signature-key.pub
openssl genrsa -out test-key.pem 4096
openssl rsa -in test-key.pem -pubout -out test-key.pub
```