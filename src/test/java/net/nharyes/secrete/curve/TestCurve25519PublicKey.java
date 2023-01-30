/*
 * Copyright 2015-2023 Luca Zanconato (<github.com/gherynos>)
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
