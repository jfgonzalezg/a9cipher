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

public class AESCipher implements Cloneable {
	private byte[] aesKey;
	
	public AESCipher(byte[] key) throws Exception {
		if (key.length != 16) {
			// Currently only supports 128-bit keys. Will be expaned in a future version
			throw new Exception("Key must be 16, 24, or 32 bytes long");
		} else {
			aesKey = key.clone();
		}
	}
	
	public byte[] encrypt(byte[] plaintext) throws Exception {
		if (plaintext.length != 16) {
			throw new Exception("plaintext must be 16 bytes long");
		} else {
			byte[] ciphertext = new byte[16];
			//TODO encrypt plaintext
			
			return ciphertext;
		}
	}
	
	public byte[] decrypt(byte[] ciphertext) throws Exception {
		if (ciphertext.length != 16) {
			throw new Exception("ciphertext must be 16 bytes long");
		} else {
			byte[] plaintext = new byte[16];
			//TODO decrypt ciphertext
			
			return plaintext;
		}
	}

	private byte[] aesSubBytes (byte[] B) throws Exception {
		if (B.length != 16) {
			throw new Exception("B must be 16 bytes long");
		} else {
			byte[] subbed = new byte[16];
			//TODO SubByes
			
			return subbed;
		}
	}
	
	private byte[] aesInverseSubBytes (byte[] B) throws Exception {
		if (B.length != 16) {
			throw new Exception("B must be 16 bytes long");
		} else {
			byte[] subbed = new byte[16];
			//TODO Inverse SubByes
			
			return subbed;
		}
	}
	
	private byte[] aesShiftRows (byte[] B) throws Exception {
		if (B.length != 16) {
			throw new Exception("B must be 16 bytes long");
		} else {
			byte[] shifted = new byte[16];
			//TODO ShiftRows
			
			return shifted;
		}
	}
	
	private byte[] aesInverseShiftRows (byte[] B) throws Exception {
		if (B.length != 16) {
			throw new Exception("B must be 16 bytes long");
		} else {
			byte[] shifted = new byte[16];
			//TODO Inverse ShiftRows
			
			return shifted;
		}
	}
	
	private byte[] aesMixColumns (byte[] B) throws Exception {
		if (B.length != 16) {
			throw new Exception("B must be 16 bytes long");
		} else {
			byte[] mixed = new byte[16];
			//TODO MixColumns
			
			return mixed;
		}
	}
	
	private byte[] aesInverseMixColumns (byte[] B) throws Exception {
		if (B.length != 16) {
			throw new Exception("B must be 16 bytes long");
		} else {
			byte[] mixed = new byte[16];
			//TODO Inverse MixColumns
			
			return mixed;
		}
	}
	
	private byte[] aesAddRoundKey (byte[] B, byte[] roundKey) throws Exception {
		if (B.length != 16) {
			throw new Exception("B must be 16 bytes long");
		} else if (roundKey.length != 16) {
			throw new Exception("roundKey must be 16 bytes long");
		} else {
			byte[] shifted = new byte[16];
			//TODO ShiftRows
			
			return shifted;
		}
	}
	
	private byte[][] aesMakeRoundKeys (byte[] key) throws Exception {
		if (key.length != 16) {
			throw new Exception("key must be 16 bytes long");
		} else {
			byte[][] aesRoundKeys = new byte[10][16];
			//TODO Make RoundKeys
			
			return aesRoundKeys;
		}
	}
	
	public byte[] getAesKey() {
		return aesKey;
	}

	public void setAesKey(byte[] aesKey) {
		this.aesKey = aesKey;
	}

}
