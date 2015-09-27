Secrete
=======

Secrete is a simple ECIES implementation that uses [Curve25519](http://cr.yp.to/ecdh.html).

The [Elliptic Curve Integrated Encryption Scheme](https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme) has been implemented with the following specifications:

| Item                        | Specification                       |
| --------------------------- | ----------------------------------- |
| Elliptic Curve              | Curve25519                          |
| Key Derivation Function     | KDF2                                |
| Message Authentication Code | HMAC with SHA512                    |
| Symmetric Encryption Scheme | AES-256 CBC mode with PKCS7 Padding |

using source code from existing repositories, including:

* <https://github.com/trevorbernard/curve25519-java>
* <https://github.com/bcgit/bc-java.git>

Many thanks to [Trevor Bernard](https://github.com/trevorbernard) and the guys of [The Legion of the Bouncy Castle](http://www.bouncycastle.org/java.html).

Binary version
--------------

Download the latest release:

* JAR file with dependencies: [secrete.zip](https://pkg.nharyes.net/secrete/secrete.zip)
* GPG Signature: [secrete.zip.sig](https://pkg.nharyes.net/secrete/secrete.zip.sig)

Usage
-----

### Generate the key pair:

```bash
$ java -jar secrete.jar genKeys
```

This will generate the two files `public.key` and `private.key` under the `.secrete` folder in the user's home.  
A password will be required to protect the private key.

The private key is stored using PBKDF2 with SHA-512 and AES-256 CBC mode with PKCS7 Padding.


### Export the public key:

```bash
$ java -jar secrete.jar -o <key_file> exportKey
```

### Encrypt a text message:

```bash
$ java -jar secrete.jar -k <recipient_key_file> encrypt
```

Insert the message ending with a "."; the encrypted message will be displayed encoded in Base64.

It is also possible to output the encrypted message to a binary file by specifying the "-o" option:

```bash
$ java -jar secrete.jar -k <recipient_key_file> -o <encrypted_file> encrypt
```

### Decrypt a text message:

```bash
$ java -jar secrete.jar decrypt
```

Insert the Base64 encrypted message and the password to unlock the private key.

It is also possible to load the encrypted message from the binary file by specifying the "-i" option:

```bash
$ java -jar secrete.jar -i <encrypted_file> decrypt
```

### Encrypt a file:

```bash
$ java -jar secrete.jar -k <recipient_key_file> -i <file_to_encrypt> -o <encrypted_file> encrypt
```

### Decrypt a file:

```bash
$ java -jar secrete.jar -i <encrypted_file> -o <decrypted_file> decrypt
```

Insert the password to unlock the private key.

Copyright and license
---------------------

Copyright (C) 2015  Luca Zanconato (<luca.zanconato@nharyes.net>)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
