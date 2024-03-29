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

package net.nharyes.secrete.ecies;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import net.nharyes.secrete.curve.Curve25519Agreement;
import net.nharyes.secrete.curve.Curve25519DecryptionParameter;
import net.nharyes.secrete.curve.Curve25519EncryptionParameter;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.IESEngine;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.IESWithCipherParameters;
import org.bouncycastle.crypto.params.ParametersWithIV;

import djb.Curve25519;

public final class ECIESHelper {

    public static final int MAC_KEY_SIZE_BITS = 256;

    public static final int AES_KEY_SIZE_BITS = 256;

    public static final int IV_SIZE_BYTES = 16;

    public static final int SHARED_INFORMATION_SIZE_BYTES = 16;

    public static final String ASYMMETRIC_ALGORITHM = "Curve25519";

    public static final String ENCODING = "UTF-8";

    public static final String PRNG_ALGORITHM = "SHA1PRNG";

    private ECIESHelper() {

    }

    private static IESEngine getIESEngine() {

        return new IESEngine(new Curve25519Agreement(), new KDF2BytesGenerator(new SHA512Digest()), new HMac(new SHA512Digest()), new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()), new PKCS7Padding()));
    }

    public static ECIESMessage encryptData(PublicKey key, String data) throws ECIESException {

        try {

            SecureRandom random = SecureRandom.getInstance(PRNG_ALGORITHM);

            return encryptData(key, data, random);

        } catch (NoSuchAlgorithmException ex) {

            throw new ECIESException(String.format("%s algorithm not found", PRNG_ALGORITHM), ex);
        }
    }

    public static ECIESMessage encryptData(PublicKey key, String data, SecureRandom random) throws ECIESException {

        try {

            return encryptData(key, data.getBytes(ENCODING), false, random);

        } catch (UnsupportedEncodingException ex) {

            throw new UnsupportedOperationException(ex.getMessage(), ex);
        }
    }

    public static ECIESMessage encryptData(PublicKey key, byte[] data) throws ECIESException {

        try {

            SecureRandom random = SecureRandom.getInstance(PRNG_ALGORITHM);

            return encryptData(key, data, random);

        } catch (NoSuchAlgorithmException ex) {

            throw new ECIESException(String.format("%s algorithm not found", PRNG_ALGORITHM), ex);
        }
    }

    public static ECIESMessage encryptData(PublicKey key, byte[] data, SecureRandom random) throws ECIESException {

        return encryptData(key, data, true, random);
    }

    private static ECIESMessage encryptData(PublicKey key, byte[] data, boolean binary, SecureRandom random) throws ECIESException {

        try {

            // check key algorithm
            if (!ASYMMETRIC_ALGORITHM.equals(key.getAlgorithm())) {

                throw new ECIESException("Wrong key algorithm");
            }

            // generate shared information
            byte[] sh1 = new byte[SHARED_INFORMATION_SIZE_BYTES];
            random.nextBytes(sh1);
            byte[] sh2 = new byte[SHARED_INFORMATION_SIZE_BYTES];
            random.nextBytes(sh2);
            byte[] iv = new byte[IV_SIZE_BYTES];
            random.nextBytes(iv);

            // generate R
            byte[] r = new byte[Curve25519.KEY_SIZE];
            random.nextBytes(r);
            byte[] curveR = new byte[Curve25519.KEY_SIZE];
            Curve25519.curve(curveR, r, null);

            // IES engine
            IESEngine ies = getIESEngine();

            // initialize engine
            Curve25519EncryptionParameter ep = new Curve25519EncryptionParameter(key.getEncoded(), r);
            ParametersWithIV p = new ParametersWithIV(new IESWithCipherParameters(sh1, sh2, MAC_KEY_SIZE_BITS, AES_KEY_SIZE_BITS), iv);
            ies.init(true, null, ep, p);

            // encrypt data
            byte[] cd = ies.processBlock(data, 0, data.length);

            // return message
            return new ECIESMessage(sh1, sh2, iv, curveR, cd, binary);

        } catch (InvalidCipherTextException ex) {

            throw new ECIESException("Message corrupted or wrong key", ex);
        }
    }

    public static byte[] decryptMessage(PrivateKey key, ECIESMessage message) throws ECIESException {

        try {

            // check key algorithm
            if (!ASYMMETRIC_ALGORITHM.equals(key.getAlgorithm())) {

                throw new ECIESException("Wrong key algorithm");
            }

            // IES engine
            IESEngine ies = getIESEngine();

            // initialize engine
            Curve25519DecryptionParameter ep = new Curve25519DecryptionParameter(key.getEncoded(), message.getR());
            ParametersWithIV p = new ParametersWithIV(new IESWithCipherParameters(message.getSh1(), message.getSh2(), MAC_KEY_SIZE_BITS, AES_KEY_SIZE_BITS), message.getIv());
            ies.init(false, null, ep, p);

            // decrypt and return data
            return ies.processBlock(message.getCd(), 0, message.getCd().length);

        } catch (InvalidCipherTextException ex) {

            throw new ECIESException("Message corrupted or wrong key", ex);
        }
    }
}
