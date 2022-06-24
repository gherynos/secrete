/*
 * Copyright 2015-2022 Luca Zanconato (<github.com/gherynos>)
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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;

import net.nharyes.secrete.curve.Curve25519PublicKey;
import net.nharyes.secrete.ecies.ECIESHelper;
import net.nharyes.secrete.ecies.ECIESException;
import net.nharyes.secrete.ecies.ECIESMessage;

import org.apache.commons.cli.CommandLine;

public class EncryptAction extends Action {  // NOPMD

    @Override
    public void execute(CommandLine line, SecureRandom random) throws ActionException {

        try {

            // read data
            Object data = readData(line.getOptionValue('i'), "message", line.hasOption('i'));

            // load public key
            String keyToLoad = DEFAULT_PUBLIC_KEY;
            if (line.hasOption('k')) {

                keyToLoad = line.getOptionValue('k');
            }

            try (InputStream fin = Files.newInputStream(Paths.get(keyToLoad))) {

                Curve25519PublicKey key = Curve25519PublicKey.deserialize(fin);

                // encrypt message
                ECIESMessage message;
                if (line.hasOption('i')) {

                    message = ECIESHelper.encryptData(key, (byte[]) data, random);

                } else {

                    message = ECIESHelper.encryptData(key, (String) data, random);
                }

                // write message
                ByteArrayOutputStream bout = new ByteArrayOutputStream();
                message.serialize(bout);
                writeData(bout.toByteArray(), line.getOptionValue('o'), true);
            }

        } catch (IOException | ECIESException ex) {

            // re-throw exception
            throw new ActionException(ex.getMessage(), ex);
        }
    }
}
