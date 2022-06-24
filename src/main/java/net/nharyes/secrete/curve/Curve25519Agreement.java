/*
 * Copyright 2015-2022 Luca Zanconato (<github.com/gherynos>)
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

import java.math.BigInteger;
import java.util.Arrays;

import org.bouncycastle.crypto.BasicAgreement;
import org.bouncycastle.crypto.CipherParameters;

import djb.Curve25519;

public class Curve25519Agreement implements BasicAgreement {  // NOPMD

    @Override
    public void init(CipherParameters param) {

        /* initialization parameters ignored */
    }

    @Override
    public int getFieldSize() {

        return Curve25519.KEY_SIZE;
    }

    @Override
    public BigInteger calculateAgreement(CipherParameters param) {

        // check class
        byte[] s = new byte[Curve25519.KEY_SIZE];
        if (param instanceof Curve25519EncryptionParameter) {

            // compute shared secret for encryption
            Curve25519EncryptionParameter cpk = (Curve25519EncryptionParameter) param;
            Curve25519.curve(s, cpk.getScalarR(), cpk.getKey());

        } else if (param instanceof Curve25519DecryptionParameter) {

            // compute shared secret for decryption
            Curve25519DecryptionParameter cpk = (Curve25519DecryptionParameter) param;
            Curve25519.curve(s, cpk.getKey(), cpk.getPointR());

        } else {

            throw new IllegalArgumentException(String.format("%s or %s instance required", Curve25519EncryptionParameter.class.getSimpleName(), Curve25519DecryptionParameter.class.getSimpleName()));
        }

        // check point at infinity
        if (Arrays.equals(s, Curve25519.ZERO)) {

            throw new IllegalArgumentException("Point at Infinity");
        }

        return new BigInteger(s);
    }
}
