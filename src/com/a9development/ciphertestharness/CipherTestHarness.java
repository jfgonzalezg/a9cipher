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

package com.a9development.ciphertestharness;

import com.a9development.a9cipher.*;

public class CipherTestHarness {

	public static void main(String[] args) {
		int[] CT = {0x9e, 0xc4, 0xc1, 0x29, 0x49, 0xa4, 0xf3, 0x14, 0x74, 0xf2, 0x99, 0x05, 0x8c, 0xe2, 0xb2, 0x2a};
//		int[] K1 = {0x4d, 0x49, 0x53, 0x53, 0x49, 0x4f, 0x4e, 0x53, 0x54, 0x41, 0x54, 0x45, 0x4d, 0x45, 0x4e, 0x54};
//		int[] K2 = {0x43, 0x59, 0x42, 0x45, 0x52, 0x43, 0x4f, 0x4d, 0x43, 0x59, 0x42, 0x45, 0x52, 0x43, 0x4f, 0x4d};
		int[] K3 = {0x84, 0x81, 0xa1, 0x5c, 0xfa, 0xca, 0xb0, 0x24, 0x5a, 0x9c, 0xd2, 0x96, 0xd7, 0x98, 0xf2, 0x78};
		
		try {
			Rijndael theMission = new Rijndael(K3);
			int[] PT = theMission.decrypt(CT);
			String PTHexString = "";
			String PTString = "";
			for (int i = 0; i < 16; i++) {
				PTHexString += Integer.toString((PT[i] & 0xff) + 0x100, 16).substring(1);
				PTString += (char) (PT[i]);
			}
			System.out.println(PTHexString);
			System.out.println(PTString);
			
		} catch (Exception e) {
			System.out.println(e);
		}

	}

}
