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

public class CipherMain {

	public static void main(String[] args) {
		Scanner in = new Scanner(System.in);
		System.out.print("Enter 16-digit hex plaintext: ");
		String desPlainText = in.nextLine().toLowerCase();
		System.out.print("Enter 16-digit hex key: ");
		String desKey = in.nextLine().toLowerCase();
		
		boolean found = false;
		Pattern hexPattern = Pattern.compile("[^0-9a-f]");
		Matcher desPTMatcher = hexPattern.matcher(desPlainText);
		Matcher desKMatcher = hexPattern.matcher(desKey);
		while (desPTMatcher.find())
			found = true;
		while (desKMatcher.find())
			found = true;
		if (found) {
			System.out.println("Plaintext and key must be hex encoded");
		} else {		
			if (desPlainText.length() != 16)
				System.out.println("Plain text must be 16 digits");
			else if (desKey.length() != 16)
				System.out.println("Key must be 16 digits");
			else {
				byte[] bytePlainText = A9Utility.hexToBytes(desPlainText);
				byte[] byteKey = A9Utility.hexToBytes(desKey);
				try {
					DESCipher newDES = new DESCipher(byteKey);
					
					byte[] CTBytes = newDES.encrypt(bytePlainText);
					byte[] PTBytes = newDES.decrypt(CTBytes);
					
					String CTString = A9Utility.bytesToHex(CTBytes);
					String PTString = A9Utility.bytesToHex(PTBytes);
										
					System.out.println("Plaintext:  " + desPlainText);
					System.out.println("Key:        " + desKey);
					System.out.println("Ciphertext: " + CTString);
					System.out.println("Backtext:   " + PTString);
					
				} catch (Exception e) {
					System.out.println(e);
				}
			}
		}
		
		System.out.println("Enter 32-digit hex plaintext: ");
		String rijndaelPlainText = in.nextLine().toLowerCase();
		System.out.println("Enter 32-digit hex key: ");
		String rijndaelKey = in.nextLine().toLowerCase();
		found = false;
		Matcher rijndaelPTMatcher = hexPattern.matcher(rijndaelPlainText);
		Matcher rijndaelKMatcher = hexPattern.matcher(rijndaelKey);
		while (rijndaelPTMatcher.find())
			found = true;
		while (rijndaelKMatcher.find())
			found = true;
		if (found) {
			System.out.println("Plaintext and key must be hex encoded");
		} else {		
			if (rijndaelPlainText.length() != 32)
				System.out.println("Plain text must be 32 digits");
			else if (rijndaelKey.length() != 32)
				System.out.println("Key must be 32 digits");
			else {
				byte[] bytePT = A9Utility.hexToBytes(rijndaelPlainText);
				byte[] byteK = A9Utility.hexToBytes(rijndaelKey);

				try {
					RijndaelCipher rd = new RijndaelCipher(byteK);
					
					byte[] CTBytes = rd.encrypt(bytePT);
					byte[] PTBytes= rd.decrypt(CTBytes);
					
					String CTString = A9Utility.bytesToHex(CTBytes);
					String PTString = A9Utility.bytesToHex(PTBytes);
										
					System.out.println("Plaintext:  " + rijndaelPlainText);
					System.out.println("Key:        " + rijndaelKey);
					System.out.println("Ciphertext: " + CTString);
					System.out.println("Backtext:   " + PTString);
				} catch (Exception e) {
					System.out.println(e);
				}
			}
		}
	}

}
