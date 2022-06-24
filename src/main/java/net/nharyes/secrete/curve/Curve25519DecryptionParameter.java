/*
 * Copyright 2015-2022 Luca Zanconato (<github.com/gherynos>)
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

import org.bouncycastle.crypto.params.KeyParameter;

import djb.Curve25519;

public class Curve25519DecryptionParameter extends KeyParameter {

    private final byte[] pointR;

    public Curve25519DecryptionParameter(byte[] privateKey, byte[] pointR) {

        super(privateKey);

        if (privateKey.length != Curve25519.KEY_SIZE) {

            throw new IllegalArgumentException("Wrong size for private key");
        }

        if (pointR.length != Curve25519.KEY_SIZE) {

            throw new IllegalArgumentException("Wrong size for R");
        }

        this.pointR = pointR;
    }

    public byte[] getPointR() {

        return pointR;
    }
}
