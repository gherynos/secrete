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

import java.math.BigInteger;
import java.util.Arrays;

import org.bouncycastle.crypto.BasicAgreement;
import org.bouncycastle.crypto.CipherParameters;

import djb.Curve25519;

public class Curve25519Agreement implements BasicAgreement {  // NOPMD

    @Override
    public void init(CipherParameters param) {

        /* initialization parameters ignored */
    }

    @Override
    public int getFieldSize() {

        return Curve25519.KEY_SIZE;
    }

    @Override
    public BigInteger calculateAgreement(CipherParameters param) {

        // check class
        byte[] s = new byte[Curve25519.KEY_SIZE];
        if (param instanceof Curve25519EncryptionParameter) {

            // compute shared secret for encryption
            Curve25519EncryptionParameter cpk = (Curve25519EncryptionParameter) param;
            Curve25519.curve(s, cpk.getScalarR(), cpk.getKey());

        } else if (param instanceof Curve25519DecryptionParameter) {

            // compute shared secret for decryption
            Curve25519DecryptionParameter cpk = (Curve25519DecryptionParameter) param;
            Curve25519.curve(s, cpk.getKey(), cpk.getPointR());

        } else {

            throw new IllegalArgumentException(String.format("%s or %s instance required", Curve25519EncryptionParameter.class.getSimpleName(), Curve25519DecryptionParameter.class.getSimpleName()));
        }

        // check point at infinity
        if (Arrays.equals(s, Curve25519.ZERO)) {

            throw new IllegalArgumentException("Point at Infinity");
        }

        return new BigInteger(s);
    }
}
