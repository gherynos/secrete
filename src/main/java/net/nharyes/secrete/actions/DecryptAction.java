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

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;

import net.nharyes.secrete.curve.Curve25519PrivateKey;
import net.nharyes.secrete.ecies.ECIESHelper;
import net.nharyes.secrete.ecies.ECIESException;
import net.nharyes.secrete.ecies.ECIESMessage;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.codec.binary.Base64;

public class DecryptAction extends Action {  // NOPMD

    @Override
    public void execute(CommandLine line, SecureRandom random) throws ActionException {

        try {

            // read data
            Object data = readData(line.getOptionValue('i'), "encrypted message");

            // get message
            ByteArrayInputStream in;
            if (line.hasOption('i')) {

                in = new ByteArrayInputStream((byte[]) data);

            } else {

                in = new ByteArrayInputStream(Base64.decodeBase64((String) data));
            }
            ECIESMessage message = ECIESMessage.deserialize(in);

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
