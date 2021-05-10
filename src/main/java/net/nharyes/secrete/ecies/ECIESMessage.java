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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import net.nharyes.secrete.MagicNumbersConstants;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.util.Arrays;

import djb.Curve25519;

public class ECIESMessage {

    private final byte[] sh1;

    private final byte[] sh2;

    private final byte[] iv;

    private final byte[] r;

    private final byte[] cd;

    private final boolean binary;

    protected ECIESMessage(byte[] sh1, byte[] sh2, byte[] iv, byte[] r, byte[] cd, boolean binary) {

        this.sh1 = sh1;
        this.sh2 = sh2;
        this.iv = iv;
        this.r = r;
        this.cd = cd;
        this.binary = binary;
    }

    public byte[] getSh1() {

        return sh1;
    }

    public byte[] getSh2() {

        return sh2;
    }

    public byte[] getIv() {

        return iv;
    }

    public byte[] getR() {

        return r;
    }

    public byte[] getCd() {

        return cd;
    }

    public boolean isBinary() {

        return binary;
    }

    public void serialize(OutputStream out) throws IOException {

        // write magic number
        if (binary) {

            out.write(MagicNumbersConstants.BINARY_MESSAGE);

        } else {

            out.write(MagicNumbersConstants.TEXT_MESSAGE);
        }

        // write message components
        out.write(sh1);
        out.write(sh2);
        out.write(iv);
        out.write(r);
        out.flush();

        // write CD size
        ByteBuffer b = ByteBuffer.allocate(4);
        b.order(ByteOrder.BIG_ENDIAN);
        b.putInt(cd.length);
        out.write(b.array());
        out.flush();

        // write CD
        out.write(cd);
        out.flush();
    }

    public static ECIESMessage deserialize(InputStream in) throws IOException {

        // check magic number
        boolean binary;
        byte[] mn = new byte[MagicNumbersConstants.TEXT_MESSAGE.length];
        IOUtils.readFully(in, mn, 0, mn.length);
        if (Arrays.areEqual(mn, MagicNumbersConstants.TEXT_MESSAGE)) {

            binary = false;

        } else if (Arrays.areEqual(mn, MagicNumbersConstants.BINARY_MESSAGE)) {

            binary = true;

        } else {

            throw new IllegalArgumentException("Wrong file format");
        }

        // read message components
        byte[] sh1 = new byte[ECIESHelper.SHARED_INFORMATION_SIZE_BYTES];
        IOUtils.readFully(in, sh1, 0, sh1.length);
        byte[] sh2 = new byte[ECIESHelper.SHARED_INFORMATION_SIZE_BYTES];
        IOUtils.readFully(in, sh2, 0, sh2.length);
        byte[] iv = new byte[ECIESHelper.IV_SIZE_BYTES];
        IOUtils.readFully(in, iv, 0, iv.length);
        byte[] r = new byte[Curve25519.KEY_SIZE];
        IOUtils.readFully(in, r, 0, r.length);

        // read CD size
        byte[] cdSizeB = new byte[4];
        IOUtils.readFully(in, cdSizeB, 0, cdSizeB.length);
        int cdSize = ByteBuffer.wrap(cdSizeB).getInt();

        // read CD
        byte[] cd = new byte[cdSize];
        IOUtils.readFully(in, cd, 0, cd.length);

        return new ECIESMessage(sh1, sh2, iv, r, cd, binary);
    }
}
