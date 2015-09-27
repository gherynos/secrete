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

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import djb.Curve25519;

public class Curve25519KeyPairGenerator {

	public static KeyPair generateKeyPair(SecureRandom random) {

		// generate private key
		byte[] pri = new byte[Curve25519.KEY_SIZE];
		random.nextBytes(pri);

		// generate public key
		byte[] pub = new byte[Curve25519.KEY_SIZE];
		Curve25519.keygen(pub, null, pri);

		// return key pair
		return new KeyPair(new Curve25519PublicKey(pub), new Curve25519PrivateKey(pri));
	}

	public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {

		SecureRandom random = SecureRandom.getInstance("SHA1PRNG");

		return generateKeyPair(random);
	}
}
