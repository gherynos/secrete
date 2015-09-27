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

package net.nharyes.secrete.ecies;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;

import org.junit.Test;

import djb.Curve25519;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class TestECIESMessage {

	@Test
	public void testMessageSerialization() throws Exception {
		
		testSer(true);
		testSer(false);
	}
	
	private void testSer(boolean binary) throws Exception {
		
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
		
		byte[] sh1 = new byte[ECIES.SHARED_INFORMATION_SIZE_BYTES];
		random.nextBytes(sh1);
		byte[] sh2 = new byte[ECIES.SHARED_INFORMATION_SIZE_BYTES];
		random.nextBytes(sh2);
		byte[] iv = new byte[ECIES.IV_SIZE_BYTES];
		random.nextBytes(iv);
		byte[] R = new byte[Curve25519.KEY_SIZE];
		random.nextBytes(R);
		byte[] cd = new byte[237];
		random.nextBytes(cd);
		
		ECIESMessage message = new ECIESMessage(sh1, sh2, iv, R, cd, binary);
		
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		message.serialize(out);
		out.close();
		
		byte[] ser = out.toByteArray();
		
		ECIESMessage message2 = ECIESMessage.deserialize(new ByteArrayInputStream(ser));
		
		assertArrayEquals(message.getCd(), message2.getCd());
		assertArrayEquals(message.getIv(), message2.getIv());
		assertArrayEquals(message.getR(), message2.getR());
		assertArrayEquals(message.getSh1(), message2.getSh1());
		assertArrayEquals(message.getSh2(), message2.getSh2());
		assertEquals(message.isBinary(), message2.isBinary());
	}
}
