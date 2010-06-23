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

public class A9Cipher {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
//		PT  = 0x02468aceeca86420
//		Key = 0x0f1571c947d9e859
//		CT  = 0xda02ce3a89ecac3b
		
		byte[] PT = {(byte)0x02, (byte)0x46, (byte)0x8a, (byte)0xce, (byte)0xec, (byte)0xa8, (byte)0x64, (byte)0x20};
		byte[] K = {(byte)0x0f, (byte)0x15, (byte)0x71, (byte)0xc9, (byte)0x47, (byte)0xd9, (byte)0xe8, (byte)0x59};
		byte[] CT = {(byte)0xda, (byte)0x02, (byte)0xce, (byte)0x3a, (byte)0x89, (byte)0xec, (byte)0xac, (byte)0x3b};
		
//		boolean[] PT = {false, false, false, false, false, false, true, false, false, true, false, false, false, true, true, false, true, false, false, false, true, false, true, false, true, true, false, false, true, true, true, false, true, true, true, false, true, true, false, false, true, false, true, false, true, false, false, false, false, true, true, false, false, true, false, false, false, false, true, false, false, false, false, false};
//		boolean[] K = {false, false, false, false, true, true, true, true, false, false, false, true, false, true, false, true, false, true, true, true, false, false, false, true, true, true, false, false, true, false, false, true, false, true, false, false, false, true, true, true, true, true, false, true, true, false, false, true, true, true, true, false, true, false, false, false, false, true, false, true, true, false, false, true};
//		boolean[] CT = {true, true, false, true, true, false, true, false, false, false, false, false, false, false, true, false, true, true, false, false, true, true, true, false, false, false, true, true, true, false, true, false, true, false, false, false, true, false, false, true, true, true, true, false, true, true, false, false, true, false, true, false, true, true, false, false, false, false, true, true, true, false, true, true};
		
		try {
			DES encrypter = new DES(PT, K);
			encrypter.Encrypt();
			
			System.out.println("Plain Text:  " + encrypter.getPlainTextString());
			System.out.println("Key Text:    " + encrypter.getKeyString());
			System.out.println("Cipher Text: " + encrypter.getCipherTextString());
			System.out.println("Expected CT: da02ce3a89ecac3b");
			System.out.println();
		} catch (Exception e) {
			System.out.println("Could not initialize encrypter: " + e);
		}
		
		try {
			DES decrypter = new DES(CT, K, true);
			decrypter.Decrypt();

			System.out.println("Cipher Text: " + decrypter.getCipherTextString());
			System.out.println("Key Text:    " + decrypter.getKeyString());
			System.out.println("Plain Text:  " + decrypter.getPlainTextString());
			System.out.println("Expected PT: 02468aceeca86420");
			System.out.println();
		} catch (Exception e) {
			System.out.println("Could not initialize decrypter: " + e);
		}
		
	}

}
