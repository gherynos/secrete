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

package net.nharyes.secrete.ecies;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertArrayEquals;

import java.security.KeyPair;
import java.util.Random;

import net.nharyes.secrete.curve.Curve25519KeyPairGenerator;

import org.junit.Test;

public class TestECIESHelper {

    @Test
    public void testTextEncryption() throws Exception {

        KeyPair keyPair = Curve25519KeyPairGenerator.generateKeyPair();

        String text = "A sample text message to encrypt...àáäæëéœ";

        ECIESMessage message = ECIESHelper.encryptData(keyPair.getPublic(), text);

        assertFalse(message.isBinary());

        byte[] data = ECIESHelper.decryptMessage(keyPair.getPrivate(), message);

        assertEquals(new String(data, ECIESHelper.ENCODING), text);

        keyPair = Curve25519KeyPairGenerator.generateKeyPair();

        try {

            ECIESHelper.decryptMessage(keyPair.getPrivate(), message);

            throw new Exception();

        } catch (ECIESException ex) {

            assertTrue(true);
        }
    }

    @Test
    public void testByteArrayEncryption() throws Exception {

        KeyPair keyPair = Curve25519KeyPairGenerator.generateKeyPair();

        Random r = new Random();
        byte[] bytes = new byte[r.nextInt(2049)];
        r.nextBytes(bytes);

        ECIESMessage message = ECIESHelper.encryptData(keyPair.getPublic(), bytes);

        assertTrue(message.isBinary());

        byte[] data = ECIESHelper.decryptMessage(keyPair.getPrivate(), message);

        assertArrayEquals(bytes, data);

        keyPair = Curve25519KeyPairGenerator.generateKeyPair();

        try {

            ECIESHelper.decryptMessage(keyPair.getPrivate(), message);

            throw new Exception();

        } catch (ECIESException ex) {

            assertTrue(true);
        }
    }
}
