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
