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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.PublicKey;

import net.nharyes.secrete.MagicNumbers;

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
		byte[] mn = new byte[MagicNumbers.PUBLIC_KEY.length];
		IOUtils.readFully(in, mn, 0, mn.length);
		if (!Arrays.areEqual(mn, MagicNumbers.PUBLIC_KEY))
			throw new IllegalArgumentException("Wrong key file format");

		// read key
		byte[] key = new byte[Curve25519.KEY_SIZE];
		IOUtils.readFully(in, key, 0, key.length);

		// return key instance
		return new Curve25519PublicKey(key);
	}

	public void serialize(OutputStream out) throws IOException {

		// write magic number
		out.write(MagicNumbers.PUBLIC_KEY);
		out.flush();

		// write key
		out.write(key);
		out.flush();
	}
}
