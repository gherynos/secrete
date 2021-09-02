/*
 * Copyright 2015-2021 Luca Zanconato (<github.com/gherynos>)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.nharyes.secrete.curve;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import djb.Curve25519;

public final class Curve25519KeyPairGenerator {  //NOPMD

    private Curve25519KeyPairGenerator() {

    }

    public static KeyPair generateKeyPair(SecureRandom random) {

        // generate private key
        byte[] pri = new byte[Curve25519.KEY_SIZE];
        random.nextBytes(pri);

        // generate public key
        byte[] pub = new byte[Curve25519.KEY_SIZE];
        Curve25519.keygen(pub, null, pri);

        // return key pair
        return new KeyPair(new Curve25519PublicKey(pub), new Curve25519PrivateKey(pri));
    }

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {

        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");

        return generateKeyPair(random);
    }
}
