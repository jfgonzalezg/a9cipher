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

// A wrapper around the RijndaelCipher class that lets it be used as AESCipher
// as well. This provides no new functionality other than to allow the
// RijndaelCipher class to be called something else.
public class AES {
	private Rijndael rd;
	
	public AES(int[] key) throws Exception {
		rd = new Rijndael(key);
	}
	
	public int[] encrypt(int[] plaintext) throws Exception {
		return rd.encrypt(plaintext);
	}
	
	public int[] decrypt(int[] ciphertext) throws Exception {
		return rd.decrypt(ciphertext);
	}
	
	public int[] getAesKey() {
		return rd.getRijndaelKey();
	}

	public void setAESKey(int[] aesKey) {
		rd.setRijndaelKey(aesKey);
	}

}
