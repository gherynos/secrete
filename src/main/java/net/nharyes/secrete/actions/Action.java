/**
 * Copyright (C) 2015  Luca Zanconato (<luca.zanconato@nharyes.net>)
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
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.SecureRandom;

import net.nharyes.secrete.Main;
import net.nharyes.secrete.ecies.ECIES;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;

public abstract class Action {

	static final String DEFAULT_PUBLIC_KEY = String.format("%s%cpublic.key", Main.getProgramFolder(), File.separatorChar);
	
	static final String DEFAULT_PRIVATE_KEY = String.format("%s%cprivate.key", Main.getProgramFolder(), File.separatorChar);
	
	public abstract void execute(CommandLine line, SecureRandom random) throws ActionException;

	Console getConsole() throws ActionException {

		// check console
		Console c = System.console();
		if (c == null) {

			// console not available
			throw new ActionException("Console not available");
		}

		return c;
	}

	Object readData(String file, String type) throws IOException, ActionException {

		if (file == null) {

			// get console
			Console c = getConsole();

			// read message
			System.out.println(String.format("Insert %s and end with '.'", type));
			String read;
			StringBuilder sb = new StringBuilder();
			do {

				read = c.readLine();
				if (!read.equalsIgnoreCase(".")) {

					sb.append(read);
					sb.append("\n");
				}

			} while (!read.equalsIgnoreCase("."));

			return sb.toString();

		} else {

			// load file
			FileInputStream fin = new FileInputStream(file);
			byte[] bData = new byte[fin.available()];
			IOUtils.readFully(fin, bData);
			fin.close();

			return bData;
		}
	}

	void writeData(byte[] data, String file, boolean binary) throws IOException {

		if (file != null) {

			// write data
			FileOutputStream fout = new FileOutputStream(file);
			fout.write(data);
			fout.close();

		} else {

			// output data
			String sData;
			if (binary)
				sData = new String(Base64.encodeBase64(data, true, false), ECIES.ENCODING);
			else
				sData = new String(data, ECIES.ENCODING);
			System.out.println(String.format("%n---%n%s", sData));
		}
	}
}
