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
import java.security.KeyPair;
import java.util.Random;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import djb.Curve25519;

public class TestCurve25519Agreement {

    @Test
    public void testAgreement() throws Exception {

        KeyPair keyPair = Curve25519KeyPairGenerator.generateKeyPair();

        Curve25519Agreement agreement = new Curve25519Agreement();

        Random r = new Random();
        byte[] scalarR = new byte[Curve25519.KEY_SIZE];
        r.nextBytes(scalarR);
        byte[] pointR = new byte[Curve25519.KEY_SIZE];
        Curve25519.curve(pointR, scalarR, null);

        BigInteger i1 = agreement.calculateAgreement(new Curve25519EncryptionParameter(keyPair.getPublic().getEncoded(), scalarR));
        BigInteger i2 = agreement.calculateAgreement(new Curve25519DecryptionParameter(keyPair.getPrivate().getEncoded(), pointR));

        assertEquals(i1, i2);
    }
}
