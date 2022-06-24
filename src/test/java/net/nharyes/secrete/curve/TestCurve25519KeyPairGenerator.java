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

import static org.junit.Assert.assertEquals;

import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Arrays;

import org.junit.Test;

import djb.Curve25519;

public class TestCurve25519KeyPairGenerator {

    @Test
    public void testKeyGeneration() throws Exception {

        KeyPair keyPair = Curve25519KeyPairGenerator.generateKeyPair();

        assertEquals(keyPair.getPublic().getClass(), Curve25519PublicKey.class);
        assertEquals(keyPair.getPublic().getAlgorithm(), "Curve25519");
        assertEquals(keyPair.getPublic().getEncoded().length, Curve25519.KEY_SIZE);

        assertEquals(keyPair.getPrivate().getClass(), Curve25519PrivateKey.class);
        assertEquals(keyPair.getPrivate().getAlgorithm(), "Curve25519");
        assertEquals(keyPair.getPrivate().getEncoded().length, Curve25519.KEY_SIZE);
    }

    @SuppressWarnings("serial")
    @Test
    public void testClamp() {

        KeyPair keyPair = Curve25519KeyPairGenerator.generateKeyPair(new SecureRandom() {

            @Override
            public synchronized void nextBytes(byte[] bytes) {

                Arrays.fill(bytes, (byte) 112);
            }
        });

        byte[] data = keyPair.getPrivate().getEncoded();
        byte b1 = (byte) 112;
        b1 &= 0xF8;
        byte b2 = (byte) 112;
        b2 &= 0x7F;
        b2 |= 0x40;
        assertEquals(data[0], b1);
        assertEquals(data[31], b2);
    }
}
