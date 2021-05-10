/*
 * Copyright (C) 2015-2021  Luca Zanconato (<github.com/gherynos>)
 *
 * This file is part of Secrete.
 *
 * Secrete is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Secrete is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Secrete.  If not, see <http://www.gnu.org/licenses/>.
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
