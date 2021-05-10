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

package net.nharyes.secrete.curve;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.Security;
import java.security.spec.KeySpec;
import java.util.Random;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

public class TestCurve25519PrivateKey {

    @Test
    public void testPrivateKeySerialization() throws Exception {

        KeyPair keyPair = Curve25519KeyPairGenerator.generateKeyPair();

        Curve25519PrivateKey pkey = (Curve25519PrivateKey) keyPair.getPrivate();

        ByteArrayOutputStream bout = new ByteArrayOutputStream();

        char[] password = "aSimplePasswordToTest".toCharArray();

        pkey.serialize(bout, password);

        byte[] serialized = bout.toByteArray();

        ByteArrayInputStream bin = new ByteArrayInputStream(serialized);

        Curve25519PrivateKey pkeyCopy = Curve25519PrivateKey.deserialize(bin, password);

        assertEquals(pkey.getAlgorithm(), pkeyCopy.getAlgorithm());
        assertEquals(pkey.getFormat(), pkeyCopy.getFormat());
        assertArrayEquals(pkey.getEncoded(), pkeyCopy.getEncoded());
    }

    @Test
    public void testPBKDF() throws Exception {

        Security.addProvider(new BouncyCastleProvider());

        Random r = new Random();

        char[] cPassword = "ThePa55wordToU5e".toCharArray();
        byte[] salt = new byte[64];
        r.nextBytes(salt);

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        KeySpec keyspec = new PBEKeySpec(cPassword, salt, 5000, 256);
        Key key = factory.generateSecret(keyspec);
        byte[] k1 = key.getEncoded();

        factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1", "BC");
        key = factory.generateSecret(keyspec);
        byte[] k2 = key.getEncoded();

        assertArrayEquals(k1, k2);

        PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(new SHA1Digest());
        gen.init(new String(cPassword).getBytes(StandardCharsets.UTF_8), salt, 5000);
        byte[] k3 = ((KeyParameter) gen.generateDerivedParameters(256)).getKey();

        assertArrayEquals(k1, k3);
        assertArrayEquals(k2, k3);
    }
}
