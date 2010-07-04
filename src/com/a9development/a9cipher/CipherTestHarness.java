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

public class CipherTestHarness {

	public static void main(String[] args) {
		Scanner in = new Scanner(System.in);
//		System.out.print("Enter 16-digit hex plaintext: ");
//		String desPlainText = in.nextLine().toLowerCase();
//		System.out.print("Enter 16-digit hex key: ");
//		String desKey = in.nextLine().toLowerCase();
		
		boolean found = false;
		Pattern hexPattern = Pattern.compile("[^0-9a-f]");
//		Matcher desPTMatcher = hexPattern.matcher(desPlainText);
//		Matcher desKMatcher = hexPattern.matcher(desKey);
//		while (desPTMatcher.find())
//			found = true;
//		while (desKMatcher.find())
//			found = true;
//		if (found) {
//			System.out.println("Plaintext and key must be hex encoded");
//		} else {		
//			if (desPlainText.length() != 16)
//				System.out.println("Plain text must be 16 digits");
//			else if (desKey.length() != 16)
//				System.out.println("Key must be 16 digits");
//			else {
//				byte[] bytePlainText = new byte[8];
//				byte[] byteKey = new byte[8];
//				for (int i = 0; i < 16; i+=2) {
//					bytePlainText[i/2] = (byte) ((Character.digit(desPlainText.charAt(i), 16) << 4) + Character.digit(desPlainText.charAt(i+1), 16));
//					byteKey[i/2] = (byte) ((Character.digit(desKey.charAt(i), 16) << 4) + Character.digit(desKey.charAt(i+1), 16));
//				}
//				try {
//					DESCipher newDES = new DESCipher(byteKey);
//					byte[] CTBytes = newDES.encrypt(bytePlainText);
//					byte[] PTBytes = newDES.decrypt(CTBytes);
//					
//					String CTString = "";
//					String PTString = "";
//					for (int i = 0; i < 8; i++) {
//						CTString += Integer.toString((CTBytes[i] & 0xff) + 0x100, 16).substring(1);
//						PTString += Integer.toString((PTBytes[i] & 0xff) + 0x100, 16).substring(1);
//					}
//					
//					System.out.println("Plaintext:  " + desPlainText);
//					System.out.println("Key:        " + desKey);
//					System.out.println("Ciphertext: " + CTString);
//					System.out.println("Backtext:   " + PTString);
//					
//				} catch (Exception e) {
//					System.out.println(e);
//				}
//			}
//		}
		
		System.out.println("Enter 32-digit hex plaintext: ");
		String aesPlainText = in.nextLine().toLowerCase();
		System.out.println("Enter 32-digit hex key: ");
		String aesKey = in.nextLine().toLowerCase();
		found = false;
		Matcher aesPTMatcher = hexPattern.matcher(aesPlainText);
		Matcher aesKMatcher = hexPattern.matcher(aesKey);
		while (aesPTMatcher.find())
			found = true;
		while (aesKMatcher.find())
			found = true;
		if (found) {
			System.out.println("Plaintext and key must be hex encoded");
		} else {		
			if (aesPlainText.length() != 32)
				System.out.println("Plain text must be 32 digits");
			else if (aesKey.length() != 32)
				System.out.println("Key must be 32 digits");
			else {
				byte[] bytePlainText = new byte[16];
				byte[] byteKey = new byte[16];
				for (int i = 0; i < 32; i+=2) {
					bytePlainText[i/2] = (byte) ((Character.digit(aesPlainText.charAt(i), 16) << 4) + Character.digit(aesPlainText.charAt(i+1), 16));
					byteKey[i/2] = (byte) ((Character.digit(aesKey.charAt(i), 16) << 4) + Character.digit(aesKey.charAt(i+1), 16));
				}
				try {
					AESCipher newAES = new AESCipher(byteKey);
					byte[] CTBytes = newAES.encrypt(bytePlainText);
//					byte[] PTBytes= newAES.decrypt(CTBytes);
					
					String CTString = "";
//					String PTString = "";
					for (int i = 0; i < 16; i++) {
						CTString += Integer.toString((CTBytes[i] & 0xff) + 0x100, 16).substring(1);
//						PTString += Integer.toString((PTBytes[i] & 0xff) + 0x100, 16).substring(1);
					}
					
					System.out.println("Plaintext:  " + aesPlainText);
					System.out.println("Key:        " + aesKey);
					System.out.println("Ciphertext: " + CTString);
//					System.out.println("Backtext:   " + PTString);
				} catch (Exception e) {
					System.out.println(e);
				}
			}
		}
	}

}
