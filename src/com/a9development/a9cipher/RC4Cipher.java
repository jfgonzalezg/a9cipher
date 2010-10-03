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

@Deprecated
public class RC4Cipher {
	private int[] S;
	private int[] T;
	private int keylen;
	private static final String ALGORITHM = "RC4";
	
	public RC4Cipher(byte[] key) throws Exception {
		if (key.length < 1 || key.length > 256) {
			throw new Exception("key must be between 1 and 256 bytes");
		} else {
			keylen = key.length;
			S = new int[256];
			T = new int[256];
			for (int i = 0; i < 256; i++) {
				S[i] = i;
				T[i] = key[i % keylen];
			}
			int j = 0;
			for (int i = 0; i < 256; i++) {
				j = (j + S[i] + T[i]) % 256;
				S[i] ^= S[j];
				S[j] ^= S[i];
				S[i] ^= S[j];
			}
		}
	}
	
	public byte[] encrypt(byte[] plaintext) {
		byte[] ciphertext = new byte[plaintext.length];
		int i = 0, j = 0, k, t;
		for (int counter = 0; counter < plaintext.length; counter++) {
			i = (i + 1) % 256;
			j = (j + S[i]) % 256;
			S[i] ^= S[j];
			S[j] ^= S[i];
			S[i] ^= S[j];
			t = (S[i] + S[j]) % 256;
			k = S[t];
			ciphertext[counter] = (byte) (plaintext[counter] ^ k);
		}
		return ciphertext;
	}
	
	public byte[] decrypt(byte[] ciphertext) {
		return encrypt(ciphertext);
	}
	
	public String getAlgorithm() {
		return ALGORITHM;
	}
}
