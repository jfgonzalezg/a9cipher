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

package com.a9development.a9cipher;

import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class A9Cipher {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		Scanner in = new Scanner(System.in);
		System.out.print("Enter 16-digit hex plaintext: ");
		String userPlainText = in.nextLine().toLowerCase();
		System.out.print("Enter 16-digit hex key: ");
		String userKey = in.nextLine().toLowerCase();
		
		boolean found = false;
		Pattern hexPattern = Pattern.compile("[^0-9a-f]");
		Matcher PTMatcher = hexPattern.matcher(userPlainText);
		Matcher KMatcher = hexPattern.matcher(userKey);
		while (PTMatcher.find())
			found = true;
		while (KMatcher.find())
			found = true;
		if (found) {
			System.out.println("Plaintext and key must be hex encoded");
		} else {		
			if (userPlainText.length() != 16)
				System.out.println("Plain text must be 16 digits");
			else if (userKey.length() != 16)
				System.out.println("Key must be 16 digits");
			else {
				byte[] bytePlainText = new byte[8];
				byte[] byteKey = new byte[8];
				for (int i = 0; i < 16; i+=2) {
					bytePlainText[i/2] = (byte) ((Character.digit(userPlainText.charAt(i), 16) << 4) + Character.digit(userPlainText.charAt(i+1), 16));
					byteKey[i/2] = (byte) ((Character.digit(userKey.charAt(i), 16) << 4) + Character.digit(userKey.charAt(i+1), 16));
				}
				try {
					DES theDES = new DES(bytePlainText, byteKey);
					theDES.Encrypt();
					System.out.println("Plaintext:  " + userPlainText);
					System.out.println("Key:        " + userKey);
					System.out.println("Ciphertext: " + theDES.getCipherTextString());
				} catch (Exception e) {
					System.out.println(e);
				}
			}
		}

	}

}
