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

import java.io.ByteArrayInputStream;
import java.io.Console;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;

import net.nharyes.secrete.curve.Curve25519PrivateKey;
import net.nharyes.secrete.ecies.ECIESHelper;
import net.nharyes.secrete.ecies.ECIESException;
import net.nharyes.secrete.ecies.ECIESMessage;

import org.apache.commons.cli.CommandLine;

public class DecryptAction extends Action {  // NOPMD

    @Override
    public void execute(CommandLine line, SecureRandom random) throws ActionException {

        try {

            // read data
            byte[] data = (byte[]) readData(line.getOptionValue('i'), "encrypted message", true);

            // get message
            ECIESMessage message;
            try (ByteArrayInputStream in = new ByteArrayInputStream(data)) {

                message = ECIESMessage.deserialize(in);
            }

            // ask password
            Console c = System.console();
            char[] password = c.readPassword("Enter password: ");

            // load private key
            try (InputStream fin = Files.newInputStream(Paths.get(DEFAULT_PRIVATE_KEY))) {

                Curve25519PrivateKey key = Curve25519PrivateKey.deserialize(fin, password);

                // decrypt message
                byte[] plaintext = ECIESHelper.decryptMessage(key, message);

                // write message
                writeData(plaintext, line.getOptionValue('o'), message.isBinary());
            }

        } catch (IOException | ECIESException ex) {

            // re-throw exception
            throw new ActionException(ex.getMessage(), ex);
        }
    }
}
