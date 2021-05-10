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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyPair;

import org.junit.Test;

public class TestCurve25519PublicKey {

    @Test
    public void testPublicKeySerialization() throws Exception {

        KeyPair keyPair = Curve25519KeyPairGenerator.generateKeyPair();

        Curve25519PublicKey pkey = (Curve25519PublicKey) keyPair.getPublic();

        ByteArrayOutputStream bout = new ByteArrayOutputStream();

        pkey.serialize(bout);

        byte[] serialized = bout.toByteArray();

        ByteArrayInputStream bin = new ByteArrayInputStream(serialized);

        Curve25519PublicKey pkeyCopy = Curve25519PublicKey.deserialize(bin);

        assertEquals(pkey.getAlgorithm(), pkeyCopy.getAlgorithm());
        assertEquals(pkey.getFormat(), pkeyCopy.getFormat());
        assertArrayEquals(pkey.getEncoded(), pkeyCopy.getEncoded());
    }
}
