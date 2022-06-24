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

package net.nharyes.secrete;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import net.nharyes.secrete.actions.Action;
import net.nharyes.secrete.actions.ActionException;
import net.nharyes.secrete.actions.DecryptAction;
import net.nharyes.secrete.actions.EncryptAction;
import net.nharyes.secrete.actions.ExportKeyAction;
import net.nharyes.secrete.actions.GenKeysAction;

import net.nharyes.secrete.ecies.ECIESHelper;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

public final class Main {  // NOPMD

    /*
     * Version
     */
    public static final String VERSION = "1.0.3";

    /*
     * Constants
     */
    private static final String DESCRIPTION = "ECIES implementation with Curve25519.";
    private static final String JAR_FILE = "secrete.jar";

    // actions
    private final Map<String, Action> actions = new ConcurrentHashMap<>();

    // command line options
    private final Options options = new Options();

    private Main(String[] args) {

        // compose actions
        composeActions();

        // compose options
        composeOptions();

        // create the command line parser
        CommandLineParser parser = new DefaultParser();

        try {

            // parse the command line arguments
            CommandLine line = parser.parse(options, args);

            // check action
            if (line.getArgs().length < 1) {  // NOPMD

                throw new ParseException("Please specify ACTION.");
            }
            if (!actions.containsKey(line.getArgs()[0])) {

                throw new ParseException(String.format("ACTION must be one of: %s.", getActionsString()));
            }

            // instantiate secure random
            SecureRandom random = SecureRandom.getInstance(ECIESHelper.PRNG_ALGORITHM);

            // execute action
            actions.get(line.getArgs()[0]).execute(line, random);

        } catch (ParseException ex) {

            // print help
            HelpFormatter formatter = new HelpFormatter();
            System.out.println("Secrete version " + VERSION);
            System.out.println();
            formatter.printHelp(String.format("java -jar %s [OPTIONS] <ACTION>", JAR_FILE), String.format("%s%n", DESCRIPTION), options, String.format("%nACTION can be %s.", getActionsString()));
            System.out.println();

            // show error
            System.err.printf("!! %s%n%n", ex.getMessage());

            // exit with error
            System.exit(-1);

        } catch (NoSuchAlgorithmException | ActionException | IllegalArgumentException ex) {

            // show error
            System.err.printf("!! %s%n%n", ex.getMessage());

            // exit with error
            System.exit(-1);

        } catch (Throwable ex) {  // NOPMD

            // show error
            System.err.printf("!! %s%n%n", ex.getMessage());

            try (OutputStream fout = Files.newOutputStream(Paths.get(String.format("%s%clastException", getProgramFolder(), File.separatorChar)))) {

                // store exception
                ex.printStackTrace(new PrintStream(fout));
                fout.flush();

            } catch (IOException exc) {  // NOPMD

                /* exception ignored */
            }

            // exit with error
            System.exit(-1);
        }
    }

    public static String getProgramFolder() {

        String sFolder = String.format("%s%c.secrete", System.getProperty("user.home"), File.separatorChar);

        File folder = new File(sFolder);

        if (!folder.exists() && !folder.mkdirs()) {

            throw new IllegalAccessError("Unable to create folder under user's home.");
        }

        return folder.getAbsolutePath();
    }

    private void composeActions() {

        actions.put("genKeys", new GenKeysAction());
        actions.put("encrypt", new EncryptAction());
        actions.put("decrypt", new DecryptAction());
        actions.put("exportKey", new ExportKeyAction());
    }

    private String getActionsString() {

        StringBuilder sb = new StringBuilder();
        for (String a : actions.keySet()) {

            sb.append(a);
            sb.append(", ");
        }
        sb.setLength(sb.length() - 2);

        return sb.toString();
    }

    private void composeOptions() {

        // input option
        Option input = Option.builder("i").build();
        input.setLongOpt("input");
        input.setArgs(1);
        input.setArgName("path");
        input.setDescription("where path is the file to encrypt/decrypt.");
        options.addOption(input);

        // output option
        Option output = Option.builder("o").build();
        output.setLongOpt("output");
        output.setArgs(1);
        output.setArgName("path");
        output.setDescription("where path is the file where to write the encrypted/decrypted/exported data.");
        options.addOption(output);

        // key option
        Option key = Option.builder("k").build();
        key.setLongOpt("key");
        key.setArgs(1);
        key.setArgName("path");
        key.setDescription("where path is the file containing the public key to use. If not specified the default key will be used.");
        options.addOption(key);
    }

    public static void main(String[] args) {

        new Main(args);
    }
}
