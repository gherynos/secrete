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

package net.nharyes.secrete.actions;

import java.io.Console;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.SecureRandom;

import net.nharyes.secrete.curve.Curve25519KeyPairGenerator;
import net.nharyes.secrete.curve.Curve25519PrivateKey;
import net.nharyes.secrete.curve.Curve25519PublicKey;

import org.apache.commons.cli.CommandLine;
import org.bouncycastle.util.Arrays;

public class GenKeysAction extends Action {

	@Override
	public void execute(CommandLine line, SecureRandom random) throws ActionException {

		try {

			// generate keys
			KeyPair keyPair = Curve25519KeyPairGenerator.generateKeyPair(random);

			// store public key
			FileOutputStream fout = new FileOutputStream(DEFAULT_PUBLIC_KEY);
			Curve25519PublicKey pkey = (Curve25519PublicKey) keyPair.getPublic();
			pkey.serialize(fout);
			fout.flush();
			fout.close();

			// get console
			Console c = getConsole();

			// ask password
			char[] password = c.readPassword("Enter password: ");
			char[] passwordRepeated = c.readPassword("Enter again: ");

			// check password
			if (!Arrays.areEqual(password, passwordRepeated)) {

				System.err.println("The password doesn't match.");
				System.exit(-1);
			}

			// store private key
			fout = new FileOutputStream(DEFAULT_PRIVATE_KEY);
			Curve25519PrivateKey key = (Curve25519PrivateKey) keyPair.getPrivate();
			key.serialize(fout, passwordRepeated);
			fout.flush();
			fout.close();

		} catch (IOException ex) {

			// re-throw exception
			throw new ActionException(ex.getMessage(), ex);
		}
	}
}
