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

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;

import net.nharyes.secrete.Main;
import net.nharyes.secrete.ecies.ECIESHelper;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Base64OutputStream;
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

    protected Object readData(String file, String type, boolean binary) throws IOException, ActionException {

        if (file == null) {

            // get console
            Console c = getConsole();

            // read message
            System.out.printf("Insert %s and end with '%s'%n", type, END_INPUT);
            String read;
            StringBuilder sb = new StringBuilder();
            do {

                read = c.readLine();
                if (!END_INPUT.equalsIgnoreCase(read)) {

                    sb.append(read);
                    sb.append('\n');
                }

            } while (!END_INPUT.equalsIgnoreCase(read));

            if (binary) {

                return Base64.decodeBase64(sb.toString());
            }

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
            System.out.println("\n---");
            if (binary) {

                try (Base64OutputStream bout = new Base64OutputStream(System.out)) {

                    bout.write(data);
                    bout.eof();
                    bout.flush();
                }

            } else {

                System.out.print(new String(data, ECIESHelper.ENCODING));
            }

        } else {

            // write data
            try (OutputStream fout = Files.newOutputStream(Paths.get(file))) {

                fout.write(data);
            }
        }
    }
}
