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

package net.nharyes.secrete;

import org.bouncycastle.util.encoders.Hex;

public class MagicNumbers {

	public static final byte[] PRIVATE_KEY = Hex.decode("5ECC0DE0");

	public static final byte[] PUBLIC_KEY = Hex.decode("5ECC0DE1");

	public static final byte[] TEXT_MESSAGE = Hex.decode("5ECC0DE2");

	public static final byte[] BINARY_MESSAGE = Hex.decode("5ECC0DE3");
}
