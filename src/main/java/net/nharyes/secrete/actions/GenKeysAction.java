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
