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

import org.bouncycastle.crypto.params.KeyParameter;

import djb.Curve25519;

public class Curve25519EncryptionParameter extends KeyParameter {

    private final byte[] scalarR;

    public Curve25519EncryptionParameter(byte[] publicKey, byte[] scalarR) {

        super(publicKey);

        if (publicKey.length != Curve25519.KEY_SIZE) {

            throw new IllegalArgumentException("Wrong size for public key");
        }

        if (scalarR.length != Curve25519.KEY_SIZE) {

            throw new IllegalArgumentException("Wrong size for r");
        }

        this.scalarR = scalarR;
    }

    public byte[] getScalarR() {

        return scalarR;
    }
}
