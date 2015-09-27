/**
 * Copyright (C) 2015  Luca Zanconato (<luca.zanconato@nharyes.net>)
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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;

import net.nharyes.secrete.MagicNumbers;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.io.CipherInputStream;
import org.bouncycastle.crypto.io.CipherOutputStream;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

import djb.Curve25519;

public class Curve25519PrivateKey implements PrivateKey {

	private static final long serialVersionUID = 4386625506282179779L;

	private static final int PBKDF2_ITERATIONS = 5000;

	public static final int AES_KEY_SIZE_BITS = 256;

	private final byte[] key;

	protected Curve25519PrivateKey(byte[] pkey) {

		key = new byte[Curve25519.KEY_SIZE];
		System.arraycopy(pkey, 0, key, 0, key.length);
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

	public static Curve25519PrivateKey deserialize(InputStream in, char[] password) throws IOException {

		try {

			// check magic number
			byte[] mn = new byte[MagicNumbers.PRIVATE_KEY.length];
			IOUtils.readFully(in, mn, 0, mn.length);
			if (!Arrays.areEqual(mn, MagicNumbers.PRIVATE_KEY))
				throw new IllegalArgumentException("Wrong key file format");

			// read initial vector
			byte[] iv = new byte[16];
			IOUtils.readFully(in, iv, 0, iv.length);

			// read salt
			byte[] salt = new byte[64];
			IOUtils.readFully(in, salt, 0, salt.length);

			// initialize cipher
			CipherParameters params = new ParametersWithIV(new KeyParameter(deriveKey(password, salt)), iv);
			BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()), new PKCS7Padding());
			cipher.reset();
			cipher.init(false, params);

			// decrypt key
			CipherInputStream cin = new CipherInputStream(in, cipher);
			byte[] key = new byte[Curve25519.KEY_SIZE];
			IOUtils.readFully(cin, key, 0, key.length);

			// return key instance
			return new Curve25519PrivateKey(key);

		} catch (UnsupportedEncodingException ex) {

			throw new UnsupportedOperationException(ex.getMessage(), ex);
		}
	}

	public void serialize(OutputStream out, char[] password) throws IOException {

		try {

			// generate initial vector
			SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
			byte[] iv = new byte[16];
			random.nextBytes(iv);

			// generate salt
			byte[] salt = new byte[64];
			random.nextBytes(salt);

			// initialize cipher
			CipherParameters params = new ParametersWithIV(new KeyParameter(deriveKey(password, salt)), iv);
			BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()), new PKCS7Padding());
			cipher.reset();
			cipher.init(true, params);

			// write magic number
			out.write(MagicNumbers.PRIVATE_KEY);
			out.flush();

			// write initial vector and salt
			out.write(iv);
			out.write(salt);
			out.flush();

			// write encrypted key to output stream
			ByteArrayOutputStream buf = new ByteArrayOutputStream();
			CipherOutputStream cout = new CipherOutputStream(buf, cipher);
			cout.write(key);
			cout.close();
			out.write(buf.toByteArray());
			out.flush();

		} catch (UnsupportedEncodingException | NoSuchAlgorithmException ex) {

			throw new UnsupportedOperationException(ex.getMessage(), ex);
		}
	}

	private static byte[] deriveKey(char[] password, byte[] salt) throws UnsupportedEncodingException {

		// generate key using PBKDF2
		PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(new SHA512Digest());
		gen.init(new String(password).getBytes("UTF-8"), salt, PBKDF2_ITERATIONS);

		return ((KeyParameter) gen.generateDerivedParameters(AES_KEY_SIZE_BITS)).getKey();
	}
}
