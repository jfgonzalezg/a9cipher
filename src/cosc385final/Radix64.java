//    Copyright 2010 Daniel James Kotowski
//
//    This file is part of A9Cipher.
//
//    A9Cipher is free software: you can redistribute it and/or modify
//    it under the terms of the GNU Lesser General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    A9Cipher is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU Lesser General Public License for more details.
//
//    You should have received a copy of the GNU Lesser General Public License
//    along with A9Cipher.  If not, see <http://www.gnu.org/licenses/>.

package cosc385final;

public class Radix64 {

	private final static char[] code = {
			'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
			'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
			'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
			'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};
	private final static char pad = '=';
	
	
	public static String encode(byte[] b) throws Exception {
		int iLength = (b.length) / 3;
		int[] x = new int[++iLength];
		for (int i = 0; i < b.length; i++) {
			x[i / 3] |= (b[i] & 0xFF) << (16 - (8 * (i % 3)));
		}
//		int eLength = iLength * 4;
		String encoded = "";
		for (int i = 0; i < x.length; i++) {
			encoded += code[(x[i] >> 18) & 0x3F];
			encoded += code[(x[i] >> 12) & 0x3F];
			encoded += code[(x[i] >> 6) & 0x3F];
			encoded += code[(x[i] >> 0) & 0x3F];
		}
		int padLength = 4 - (((b.length + 5) / 6) % 4);
		encoded = encoded.substring(0, encoded.length() - padLength);
		for (int i = 0; i < padLength; i++) {
			encoded += pad;
		}
		return encoded;
	}
}
