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

import org.bouncycastle.crypto.params.KeyParameter;

import djb.Curve25519;

public class Curve25519DecryptionParameter extends KeyParameter {

	private byte[] pointR;
	
	public Curve25519DecryptionParameter(byte[] privateKey, byte[] pointR) {
		
		super(privateKey);
		
		if (privateKey.length != Curve25519.KEY_SIZE)
			throw new IllegalArgumentException("Wrong size for private key");
		
		if (pointR.length != Curve25519.KEY_SIZE)
			throw new IllegalArgumentException("Wrong size for R");
		
		this.pointR = pointR;
	}
	
	public byte[] getPointR() {
		
		return pointR;
	}
}
