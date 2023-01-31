# Secrete

Secrete is a simple ECIES implementation that uses [Curve25519](http://cr.yp.to/ecdh.html).

The [Elliptic Curve Integrated Encryption Scheme](https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme) has been implemented with the following specifications:

| Item                        | Specification                       |
|-----------------------------|-------------------------------------|
| Elliptic Curve              | Curve25519                          |
| Key Derivation Function     | KDF2                                |
| Message Authentication Code | HMAC with SHA512                    |
| Symmetric Encryption Scheme | AES-256 CBC mode with PKCS7 Padding |

using source code from existing repositories, including:

* <https://github.com/trevorbernard/curve25519-java>
* <https://github.com/bcgit/bc-java.git>

Many thanks to [Trevor Bernard](https://github.com/trevorbernard) and the guys of [The Legion of the Bouncy Castle](http://www.bouncycastle.org/java.html).

## Binary version

The binary distribution can be downloaded from the [releases](https://github.com/gherynos/secrete/releases) page.

## Usage

### Generate the key pair

```shell
java -jar secrete.jar genKeys
```

This will generate the two files `public.key` and `private.key` under the `.secrete` folder in the user's home.
A password will be required to protect the private key.

The private key is stored using PBKDF2 with SHA-512 and AES-256 CBC mode with PKCS7 Padding.

#### Change the private key password

To change the password of the `private.key` under the `.secrete` folder, use:

```shell
java -jar secrete.jar changePwd
```

### Export the public key

```shell
java -jar secrete.jar -o <key_file> exportKey
```

### Encrypt a text message

```shell
java -jar secrete.jar -k <recipient_key_file> encrypt
```

Insert the message ending with a "."; the encrypted message will be displayed encoded in Base64.

It is also possible to output the encrypted message to a binary file by specifying the "-o" option:

```shell
java -jar secrete.jar -k <recipient_key_file> -o <encrypted_file> encrypt
```

### Decrypt a text message

```shell
java -jar secrete.jar decrypt
```

Insert the Base64 encrypted message, and the password to unlock the private key.

It is also possible to load the encrypted message from the binary file by specifying the "-i" option:

```shell
java -jar secrete.jar -i <encrypted_file> decrypt
```

### Encrypt a file

```shell
java -jar secrete.jar -k <recipient_key_file> -i <file_to_encrypt> -o <encrypted_file> encrypt
```

### Decrypt a file

```shell
java -jar secrete.jar -i <encrypted_file> -o <decrypted_file> decrypt
```

Insert the password to unlock the private key.

## Library usage

Secrete can be used as a library, via the [Maven Central Repository](https://mvnrepository.com/artifact/net.nharyes/secrete):

```xml
<dependency>
    <groupId>net.nharyes</groupId>
    <artifactId>secrete</artifactId>
</dependency>
```

The main classes to use are:

* `net.nharyes.secrete.curve.Curve25519KeyPairGenerator`
* `net.nharyes.secrete.ecies.ECIESHelper`

Check the [ECIESHelper unit tests](https://github.com/gherynos/secrete/blob/main/src/test/java/net/nharyes/secrete/ecies/TestECIESHelper.java#L34) for some usage examples.

## Author

> GitHub [@gherynos](https://github.com/gherynos)

## License

Secrete is licensed under the [Apache License 2.0](https://apache.org/licenses/LICENSE-2.0) since version `1.0.2`.
