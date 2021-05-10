/*
 * Copyright (C) 2015-2021  Luca Zanconato (<github.com/gherynos>)
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
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.SecureRandom;

import net.nharyes.secrete.curve.Curve25519KeyPairGenerator;
import net.nharyes.secrete.curve.Curve25519PrivateKey;
import net.nharyes.secrete.curve.Curve25519PublicKey;

import org.apache.commons.cli.CommandLine;
import org.bouncycastle.util.Arrays;

public class GenKeysAction extends Action {  // NOPMD

    @Override
    public void execute(CommandLine line, SecureRandom random) throws ActionException {

        try (OutputStream pub = Files.newOutputStream(Paths.get(DEFAULT_PUBLIC_KEY));
             OutputStream pri = Files.newOutputStream(Paths.get(DEFAULT_PRIVATE_KEY))) {

            // generate keys
            KeyPair keyPair = Curve25519KeyPairGenerator.generateKeyPair(random);

            // store public key
            Curve25519PublicKey pkey = (Curve25519PublicKey) keyPair.getPublic();
            pkey.serialize(pub);
            pub.flush();

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
            Curve25519PrivateKey key = (Curve25519PrivateKey) keyPair.getPrivate();
            key.serialize(pri, passwordRepeated);
            pri.flush();

        } catch (IOException ex) {

            // re-throw exception
            throw new ActionException(ex.getMessage(), ex);
        }
    }
}
