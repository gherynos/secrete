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

package net.nharyes.secrete.ecies;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;

import org.junit.Test;

import djb.Curve25519;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class TestECIESMessage {

    @Test
    public void testMessageSerialization() throws Exception {

        testSer(true);
        testSer(false);
    }

    private void testSer(boolean binary) throws Exception {

        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");

        byte[] sh1 = new byte[ECIESHelper.SHARED_INFORMATION_SIZE_BYTES];
        random.nextBytes(sh1);
        byte[] sh2 = new byte[ECIESHelper.SHARED_INFORMATION_SIZE_BYTES];
        random.nextBytes(sh2);
        byte[] iv = new byte[ECIESHelper.IV_SIZE_BYTES];
        random.nextBytes(iv);
        byte[] R = new byte[Curve25519.KEY_SIZE];
        random.nextBytes(R);
        byte[] cd = new byte[237];
        random.nextBytes(cd);

        ECIESMessage message = new ECIESMessage(sh1, sh2, iv, R, cd, binary);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        message.serialize(out);
        out.close();

        byte[] ser = out.toByteArray();

        ECIESMessage message2 = ECIESMessage.deserialize(new ByteArrayInputStream(ser));

        assertArrayEquals(message.getCd(), message2.getCd());
        assertArrayEquals(message.getIv(), message2.getIv());
        assertArrayEquals(message.getR(), message2.getR());
        assertArrayEquals(message.getSh1(), message2.getSh1());
        assertArrayEquals(message.getSh2(), message2.getSh2());
        assertEquals(message.isBinary(), message2.isBinary());
    }
}
