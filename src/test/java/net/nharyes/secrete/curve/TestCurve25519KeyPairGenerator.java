/*
 * Copyright (C) 2015  Luca Zanconato (<github.com/gherynos>)
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
