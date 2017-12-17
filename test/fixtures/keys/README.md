Generate test keys
===

## Typical keys
``` bash
openssl genrsa -out signature-key.pem 4096
openssl rsa -in signature-key.pem -pubout -out signature-key.pub
openssl genrsa -out test-key.pem 4096
openssl rsa -in test-key.pem -pubout -out test-key.pub
```

## Smaller keys (not sure if they work)
``` bash
openssl genrsa -out small-signature-key.pem 2048
openssl rsa -in small-signature-key.pem -pubout -out small-signature-key.pub
openssl genrsa -out small-test-key.pem 2048
openssl rsa -in small-test-key.pem -pubout -out small-test-key.pub
```