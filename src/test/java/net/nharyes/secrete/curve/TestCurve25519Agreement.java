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

import java.math.BigInteger;
import java.security.KeyPair;
import java.util.Random;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import djb.Curve25519;

public class TestCurve25519Agreement {

	@Test
	public void testAgreement() throws Exception {

		KeyPair keyPair = Curve25519KeyPairGenerator.generateKeyPair();

		Curve25519Agreement agreement = new Curve25519Agreement();

		Random r = new Random();
		byte[] scalarR = new byte[Curve25519.KEY_SIZE];
		r.nextBytes(scalarR);
		byte[] pointR = new byte[Curve25519.KEY_SIZE];
		Curve25519.curve(pointR, scalarR, null);

		BigInteger i1 = agreement.calculateAgreement(new Curve25519EncryptionParameter(keyPair.getPublic().getEncoded(), scalarR));
		BigInteger i2 = agreement.calculateAgreement(new Curve25519DecryptionParameter(keyPair.getPrivate().getEncoded(), pointR));

		assertEquals(i1, i2);
	}
}
