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

package net.nharyes.secrete.actions;

import net.nharyes.secrete.curve.Curve25519PrivateKey;
import net.nharyes.secrete.curve.Curve25519PublicKey;
import net.nharyes.secrete.ecies.ECIESException;
import net.nharyes.secrete.ecies.ECIESHelper;
import net.nharyes.secrete.ecies.ECIESMessage;
import org.apache.commons.cli.CommandLine;
import org.bouncycastle.util.Arrays;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;

public class ChangePwdAction extends Action {  // NOPMD

    @Override
    public void execute(CommandLine line, SecureRandom random) throws ActionException {

        try {

            // check key existence
            Path path = Paths.get(DEFAULT_PRIVATE_KEY);
            if (!path.toFile().exists()) {

                throw new ActionException("Private key not found");
            }

            // encrypt dummy message for key verification
            ECIESMessage message;
            try (InputStream fin = Files.newInputStream(Paths.get(DEFAULT_PUBLIC_KEY))) {

                Curve25519PublicKey key = Curve25519PublicKey.deserialize(fin);
                message = ECIESHelper.encryptData(key, "Hello World!".getBytes(), random);
            }

            // ask current password
            Console c = System.console();
            char[] password = c.readPassword("Enter the current password: ");

            // load private key
            Curve25519PrivateKey key;
            try (InputStream fin = Files.newInputStream(path)) {

                key = Curve25519PrivateKey.deserialize(fin, password);

                try {

                    // check key
                    ECIESHelper.decryptMessage(key, message);

                } catch (ECIESException ex) {

                    System.err.println("Wrong password.");
                    System.exit(-1);
                }
            }

            // ask for the new password
            password = c.readPassword("Enter the new password: ");
            char[] passwordRepeated = c.readPassword("Enter the new password again: ");

            // check password
            if (!Arrays.areEqual(password, passwordRepeated)) {

                System.err.println("The password doesn't match.");
                System.exit(-1);
            }

            // store the key with the new password
            try (OutputStream pri = Files.newOutputStream(path)) {

                key.serialize(pri, passwordRepeated);
                pri.flush();
            }

        } catch (IOException | ECIESException ex) {

            // re-throw exception
            throw new ActionException(ex.getMessage(), ex);
        }
    }
}
