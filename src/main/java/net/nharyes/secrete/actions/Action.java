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

import net.nharyes.secrete.Main;
import net.nharyes.secrete.ecies.ECIESHelper;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;

public abstract class Action {

    protected static final String DEFAULT_PUBLIC_KEY = String.format("%s%cpublic.key", Main.getProgramFolder(), File.separatorChar);

    protected static final String DEFAULT_PRIVATE_KEY = String.format("%s%cprivate.key", Main.getProgramFolder(), File.separatorChar);

    protected static final String END_INPUT = ".";

    public abstract void execute(CommandLine line, SecureRandom random) throws ActionException;

    protected Action() {

    }

    protected Console getConsole() throws ActionException {

        // check console
        Console c = System.console();
        if (c == null) {

            // console not available
            throw new ActionException("Console not available");
        }

        return c;
    }

    protected Object readData(String file, String type) throws IOException, ActionException {

        if (file == null) {

            // get console
            Console c = getConsole();

            // read message
            System.out.printf("Insert %s and end with '.'%n", type);
            String read;
            StringBuilder sb = new StringBuilder();
            do {

                read = c.readLine();
                if (!END_INPUT.equalsIgnoreCase(read)) {

                    sb.append(read);
                    sb.append('\n');
                }

            } while (!END_INPUT.equalsIgnoreCase(read));

            return sb.toString();

        } else {

            // load file
            try (InputStream fin = Files.newInputStream(Paths.get(file))) {

                byte[] bData = new byte[fin.available()];
                IOUtils.readFully(fin, bData);

                return bData;
            }
        }
    }

    protected void writeData(byte[] data, String file, boolean binary) throws IOException {

        if (file == null) {

            // output data
            String sData;
            if (binary) {

                sData = new String(Base64.encodeBase64(data, true, false), ECIESHelper.ENCODING);

            } else {

                sData = new String(data, ECIESHelper.ENCODING);
            }
            System.out.printf("%n---%n%s%n", sData);

        } else {

            // write data
            try (OutputStream fout = Files.newOutputStream(Paths.get(file))) {

                fout.write(data);
            }
        }
    }
}
