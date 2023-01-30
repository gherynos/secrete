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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.PublicKey;

import net.nharyes.secrete.MagicNumbersConstants;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.util.Arrays;

import djb.Curve25519;

public class Curve25519PublicKey implements PublicKey {

    private static final long serialVersionUID = -7034768783782281104L;

    private final byte[] key;

    protected Curve25519PublicKey(byte[] pkey) {

        key = new byte[Curve25519.KEY_SIZE];
        System.arraycopy(pkey, 0, key, 0, pkey.length);
    }

    @Override
    public String getAlgorithm() {

        return "Curve25519";
    }

    @Override
    public String getFormat() {

        return null;
    }

    @Override
    public byte[] getEncoded() {

        return key;
    }

    public static Curve25519PublicKey deserialize(InputStream in) throws IOException {

        // check magic number
        byte[] mn = new byte[MagicNumbersConstants.PUBLIC_KEY.length];
        IOUtils.readFully(in, mn, 0, mn.length);
        if (!Arrays.areEqual(mn, MagicNumbersConstants.PUBLIC_KEY)) {

            throw new IllegalArgumentException("Wrong key file format");
        }

        // read key
        byte[] key = new byte[Curve25519.KEY_SIZE];
        IOUtils.readFully(in, key, 0, key.length);

        // return key instance
        return new Curve25519PublicKey(key);
    }

    public void serialize(OutputStream out) throws IOException {

        // write magic number
        out.write(MagicNumbersConstants.PUBLIC_KEY);
        out.flush();

        // write key
        out.write(key);
        out.flush();
    }
}
