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

package net.nharyes.secrete;

import java.io.*;
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

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionBuilder;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.PosixParser;

public final class Main {  // NOPMD

    /*
     * Version
     */
    public static final String VERSION = "1.0.1";

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
        CommandLineParser parser = new PosixParser();

        try {

            // parse the command line arguments
            CommandLine line = parser.parse(options, args);

            // check action
            if (line.getArgs().length < 1) {  // NOPMD

                throw new ParseException("Please specify ACTION.");
            }
            if (!actions.containsKey(line.getArgs()[0])) {

                throw new ParseException(String.format("ACTION must be %s.", getActionsString()));
            }

            // instantiate secure random
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");

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
            System.out.printf("!! %s%n%n", ex.getMessage());

            // exit with error
            System.exit(-1);

        } catch (NoSuchAlgorithmException | ActionException | IllegalArgumentException ex) {

            // show error
            System.out.printf("!! %s%n%n", ex.getMessage());

            // exit with error
            System.exit(-1);

        } catch (Throwable ex) {  // NOPMD

            // show error
            System.out.printf("!! %s%n%n", ex.getMessage());

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
        sb.replace(sb.length() - 2, sb.length(), "");

        return sb.toString();
    }

    private void composeOptions() {

        // input option
        Option input = OptionBuilder.create('i');
        input.setLongOpt("input");
        input.setArgs(1);
        input.setArgName("path");
        input.setDescription("where path is the file to encrypt/decrypt.");
        options.addOption(input);

        // output option
        Option output = OptionBuilder.create('o');
        output.setLongOpt("output");
        output.setArgs(1);
        output.setArgName("path");
        output.setDescription("where path is the file where to write the encrypted/decrypted/exported data.");
        options.addOption(output);

        // key option
        Option key = OptionBuilder.create('k');
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
