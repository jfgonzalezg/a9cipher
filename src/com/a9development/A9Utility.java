//    Copyright 2010 Daniel James Kotowski
//
//    This file is part of A9Utilities.
//
//    A9Cipher is free software: you can redistribute it and/or modify
//    it under the terms of the GNU Lesser General Public License as published
//	  by the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    A9Cipher is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU Lesser General Public License for more details.
//
//    You should have received a copy of the GNU Lesser General Public License
//    along with A9Cipher.  If not, see <http://www.gnu.org/licenses/>.

package com.a9development;

/**
 * A utility class used in many A9Development projects. All arrays are
 * big-endian (most significant bit first).
 * 
 * TODO: Add error catching to make sure all arrays are the right size
 * 
 * @author Daniel Kotowski
 * @version 0.1
 *
 */
public class A9Utility {

	/**
	 * Converts a byte array to a representative string of hex digits.
	 * @param b byte array to convert
	 * @return representative string of hex digits
	 */
	public static String bytesToHex(byte[] b) {
		String s = "";
		for (int i = 0; i < b.length; i++) {
			if (i > 0 && i % 4 == 0) {
				s += " ";
			}
			s += Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);
		}
		return s;
	}

	/**
	 * Converts a string of hex digits to a representative byte array
	 * @param s string of hex digits to convert
	 * @return representative byte array
	 */
	public static byte[] hexToBytes(String s) {
		byte[] b = new byte[s.length() / 2];
		for (int i = 0; i < s.length(); i+=2) {
			b[i/2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) 
					+ Character.digit(s.charAt(i+1), 16));
		}
		return b;
	}

	/**
	 * Converts an int to a representative byte array
	 * @param i int to convert
	 * @return representative byte array
	 */
	public static byte[] intToBytes(int i) {
		byte[] b = new byte[4];
		for (int c = 0; c < 4; c++) {
			b[c] = (byte) ((i >>> (56 - 8 * c)) & 0xff);
		}
		return b;
	}

	/**
	 * Converts a byte array to a representative int
	 * @param b byte array to convert
	 * @return representative int
	 */
	public static int bytesToInt(byte[] b) {
		return ((b[0] << 24) & 0xff000000) | ((b[1] << 16) & 0xff0000) | ((b[2] << 8) & 0xff00) | (b[3] & 0xff);
	}

	/**
	 * Converts a long to a representative byte array
	 * @param l long to convert
	 * @return representative byte array
	 */
	public static byte[] longToBytes(long l) {
		byte[] b = new byte[8];
		for (int c = 0; c < 8; c++) {
			b[c] = (byte) ((l >>> (56 - 8 * c)) & 0xffL);
		}
		return b;
	}

	/**
	 * Converts a byte to a binary array of booleans
	 * @param b byte to convert
	 * @return representative binary array
	 */
	public static boolean[] byteToBits(byte b) {
		boolean[] bits = new boolean[8];
		for (int i = 0; i < 8; i++) {
			bits[7-i] = ((b & (1 << i)) != 0);
		}
		return bits;
	}

	/**
	 * Converts a binary array of booleans to an 8-byte array
	 * @param bits binary array to convert
	 * @return representative 8-byte array
	 */
	public static byte[] bitsTo8Bytes(boolean[] bits) {
		byte[] b = new byte[8];
		for (int i = 0; i < 8; i++) {
			for (int j = 0; j < 8; j++) {
				b[i] += (((bits[(8*i)+j])?1:0) << (7-j));
			}
		}

		return b;
	}

	/**
	 * Gets the i'th bit of int x
	 * @param x int to get bit from
	 * @param i offset
	 * @return the i'th bit of x
	 */
	public static int getBit(int x, int i) {
		return (x >>> i) & 0x01;
	}

	/**
	 * Gets the i'th bit of int array x 
	 * @param x int to get bit from
	 * @param i offset
	 * @return 
	 */
	public static int getBit(int[] x, int i) {
		return (x[i / 32] >>> (i % 32)) & 0x01;
	}
	
	/**
	 * Used to set or clear a bit in an int array
	 * @param x int array
	 * @param i offset
	 * @param v if odd, set; else, clear
	 */
	public static void setBit(int[] x, int i, int v) {
		if ((v & 0x01) == 1)
			x[i / 32] |= 1 << (i % 32); // set bit
		else
			x[i / 32] &= ~(1 << (i % 32)); // clear bit
	}
	
	/**
	 * Gets the i'th 4-bit nibble from int x
	 * @param x int to get 4-bit nibble from
	 * @param i 4-bit offset
	 * @return 4-bit nibble
	 */
	public static int getNibble(int x, int i) {
		return (x >>> (4 * i)) & 0x0F;
	}
	
}
