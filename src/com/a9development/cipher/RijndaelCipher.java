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

package com.a9development.cipher;

import java.security.InvalidKeyException;

public class RijndaelCipher extends BlockCipher {
	
	private final byte[][] rijndaelSBox = {
		{(byte) 0x63, (byte) 0x7c, (byte) 0x77, (byte) 0x7b, (byte) 0xf2, (byte) 0x6b, (byte) 0x6f, (byte) 0xc5, (byte) 0x30, (byte) 0x01, (byte) 0x67, (byte) 0x2b, (byte) 0xfe, (byte) 0xd7, (byte) 0xab, (byte) 0x76},
		{(byte) 0xca, (byte) 0x82, (byte) 0xc9, (byte) 0x7d, (byte) 0xfa, (byte) 0x59, (byte) 0x47, (byte) 0xf0, (byte) 0xad, (byte) 0xd4, (byte) 0xa2, (byte) 0xaf, (byte) 0x9c, (byte) 0xa4, (byte) 0x72, (byte) 0xc0},
		{(byte) 0xb7, (byte) 0xfd, (byte) 0x93, (byte) 0x26, (byte) 0x36, (byte) 0x3f, (byte) 0xf7, (byte) 0xcc, (byte) 0x34, (byte) 0xa5, (byte) 0xe5, (byte) 0xf1, (byte) 0x71, (byte) 0xd8, (byte) 0x31, (byte) 0x15},
		{(byte) 0x04, (byte) 0xc7, (byte) 0x23, (byte) 0xc3, (byte) 0x18, (byte) 0x96, (byte) 0x05, (byte) 0x9a, (byte) 0x07, (byte) 0x12, (byte) 0x80, (byte) 0xe2, (byte) 0xeb, (byte) 0x27, (byte) 0xb2, (byte) 0x75},
		{(byte) 0x09, (byte) 0x83, (byte) 0x2c, (byte) 0x1a, (byte) 0x1b, (byte) 0x6e, (byte) 0x5a, (byte) 0xa0, (byte) 0x52, (byte) 0x3b, (byte) 0xd6, (byte) 0xb3, (byte) 0x29, (byte) 0xe3, (byte) 0x2f, (byte) 0x84},
		{(byte) 0x53, (byte) 0xd1, (byte) 0x00, (byte) 0xed, (byte) 0x20, (byte) 0xfc, (byte) 0xb1, (byte) 0x5b, (byte) 0x6a, (byte) 0xcb, (byte) 0xbe, (byte) 0x39, (byte) 0x4a, (byte) 0x4c, (byte) 0x58, (byte) 0xcf},
		{(byte) 0xd0, (byte) 0xef, (byte) 0xaa, (byte) 0xfb, (byte) 0x43, (byte) 0x4d, (byte) 0x33, (byte) 0x85, (byte) 0x45, (byte) 0xf9, (byte) 0x02, (byte) 0x7f, (byte) 0x50, (byte) 0x3c, (byte) 0x9f, (byte) 0xa8},
		{(byte) 0x51, (byte) 0xa3, (byte) 0x40, (byte) 0x8f, (byte) 0x92, (byte) 0x9d, (byte) 0x38, (byte) 0xf5, (byte) 0xbc, (byte) 0xb6, (byte) 0xda, (byte) 0x21, (byte) 0x10, (byte) 0xff, (byte) 0xf3, (byte) 0xd2},
		{(byte) 0xcd, (byte) 0x0c, (byte) 0x13, (byte) 0xec, (byte) 0x5f, (byte) 0x97, (byte) 0x44, (byte) 0x17, (byte) 0xc4, (byte) 0xa7, (byte) 0x7e, (byte) 0x3d, (byte) 0x64, (byte) 0x5d, (byte) 0x19, (byte) 0x73},
		{(byte) 0x60, (byte) 0x81, (byte) 0x4f, (byte) 0xdc, (byte) 0x22, (byte) 0x2a, (byte) 0x90, (byte) 0x88, (byte) 0x46, (byte) 0xee, (byte) 0xb8, (byte) 0x14, (byte) 0xde, (byte) 0x5e, (byte) 0x0b, (byte) 0xdb},
		{(byte) 0xe0, (byte) 0x32, (byte) 0x3a, (byte) 0x0a, (byte) 0x49, (byte) 0x06, (byte) 0x24, (byte) 0x5c, (byte) 0xc2, (byte) 0xd3, (byte) 0xac, (byte) 0x62, (byte) 0x91, (byte) 0x95, (byte) 0xe4, (byte) 0x79},
		{(byte) 0xe7, (byte) 0xc8, (byte) 0x37, (byte) 0x6d, (byte) 0x8d, (byte) 0xd5, (byte) 0x4e, (byte) 0xa9, (byte) 0x6c, (byte) 0x56, (byte) 0xf4, (byte) 0xea, (byte) 0x65, (byte) 0x7a, (byte) 0xae, (byte) 0x08},
		{(byte) 0xba, (byte) 0x78, (byte) 0x25, (byte) 0x2e, (byte) 0x1c, (byte) 0xa6, (byte) 0xb4, (byte) 0xc6, (byte) 0xe8, (byte) 0xdd, (byte) 0x74, (byte) 0x1f, (byte) 0x4b, (byte) 0xbd, (byte) 0x8b, (byte) 0x8a},
		{(byte) 0x70, (byte) 0x3e, (byte) 0xb5, (byte) 0x66, (byte) 0x48, (byte) 0x03, (byte) 0xf6, (byte) 0x0e, (byte) 0x61, (byte) 0x35, (byte) 0x57, (byte) 0xb9, (byte) 0x86, (byte) 0xc1, (byte) 0x1d, (byte) 0x9e},
		{(byte) 0xe1, (byte) 0xf8, (byte) 0x98, (byte) 0x11, (byte) 0x69, (byte) 0xd9, (byte) 0x8e, (byte) 0x94, (byte) 0x9b, (byte) 0x1e, (byte) 0x87, (byte) 0xe9, (byte) 0xce, (byte) 0x55, (byte) 0x28, (byte) 0xdf},
		{(byte) 0x8c, (byte) 0xa1, (byte) 0x89, (byte) 0x0d, (byte) 0xbf, (byte) 0xe6, (byte) 0x42, (byte) 0x68, (byte) 0x41, (byte) 0x99, (byte) 0x2d, (byte) 0x0f, (byte) 0xb0, (byte) 0x54, (byte) 0xbb, (byte) 0x16}};
	private final byte[][] rijndaelInverseSBox = {
		{(byte) 0x52, (byte) 0x09, (byte) 0x6a, (byte) 0xd5, (byte) 0x30, (byte) 0x36, (byte) 0xa5, (byte) 0x38, (byte) 0xbf, (byte) 0x40, (byte) 0xa3, (byte) 0x9e, (byte) 0x81, (byte) 0xf3, (byte) 0xd7, (byte) 0xfb},
		{(byte) 0x7c, (byte) 0xe3, (byte) 0x39, (byte) 0x82, (byte) 0x9b, (byte) 0x2f, (byte) 0xff, (byte) 0x87, (byte) 0x34, (byte) 0x8e, (byte) 0x43, (byte) 0x44, (byte) 0xc4, (byte) 0xde, (byte) 0xe9, (byte) 0xcb},
		{(byte) 0x54, (byte) 0x7b, (byte) 0x94, (byte) 0x32, (byte) 0xa6, (byte) 0xc2, (byte) 0x23, (byte) 0x3d, (byte) 0xee, (byte) 0x4c, (byte) 0x95, (byte) 0x0b, (byte) 0x42, (byte) 0xfa, (byte) 0xc3, (byte) 0x4e},
		{(byte) 0x08, (byte) 0x2e, (byte) 0xa1, (byte) 0x66, (byte) 0x28, (byte) 0xd9, (byte) 0x24, (byte) 0xb2, (byte) 0x76, (byte) 0x5b, (byte) 0xa2, (byte) 0x49, (byte) 0x6d, (byte) 0x8b, (byte) 0xd1, (byte) 0x25},
		{(byte) 0x72, (byte) 0xf8, (byte) 0xf6, (byte) 0x64, (byte) 0x86, (byte) 0x68, (byte) 0x98, (byte) 0x16, (byte) 0xd4, (byte) 0xa4, (byte) 0x5c, (byte) 0xcc, (byte) 0x5d, (byte) 0x65, (byte) 0xb6, (byte) 0x92},
		{(byte) 0x6c, (byte) 0x70, (byte) 0x48, (byte) 0x50, (byte) 0xfd, (byte) 0xed, (byte) 0xb9, (byte) 0xda, (byte) 0x5e, (byte) 0x15, (byte) 0x46, (byte) 0x57, (byte) 0xa7, (byte) 0x8d, (byte) 0x9d, (byte) 0x84},
		{(byte) 0x90, (byte) 0xd8, (byte) 0xab, (byte) 0x00, (byte) 0x8c, (byte) 0xbc, (byte) 0xd3, (byte) 0x0a, (byte) 0xf7, (byte) 0xe4, (byte) 0x58, (byte) 0x05, (byte) 0xb8, (byte) 0xb3, (byte) 0x45, (byte) 0x06},
		{(byte) 0xd0, (byte) 0x2c, (byte) 0x1e, (byte) 0x8f, (byte) 0xca, (byte) 0x3f, (byte) 0x0f, (byte) 0x02, (byte) 0xc1, (byte) 0xaf, (byte) 0xbd, (byte) 0x03, (byte) 0x01, (byte) 0x13, (byte) 0x8a, (byte) 0x6b},
		{(byte) 0x3a, (byte) 0x91, (byte) 0x11, (byte) 0x41, (byte) 0x4f, (byte) 0x67, (byte) 0xdc, (byte) 0xea, (byte) 0x97, (byte) 0xf2, (byte) 0xcf, (byte) 0xce, (byte) 0xf0, (byte) 0xb4, (byte) 0xe6, (byte) 0x73},
		{(byte) 0x96, (byte) 0xac, (byte) 0x74, (byte) 0x22, (byte) 0xe7, (byte) 0xad, (byte) 0x35, (byte) 0x85, (byte) 0xe2, (byte) 0xf9, (byte) 0x37, (byte) 0xe8, (byte) 0x1c, (byte) 0x75, (byte) 0xdf, (byte) 0x6e},
		{(byte) 0x47, (byte) 0xf1, (byte) 0x1a, (byte) 0x71, (byte) 0x1d, (byte) 0x29, (byte) 0xc5, (byte) 0x89, (byte) 0x6f, (byte) 0xb7, (byte) 0x62, (byte) 0x0e, (byte) 0xaa, (byte) 0x18, (byte) 0xbe, (byte) 0x1b},
		{(byte) 0xfc, (byte) 0x56, (byte) 0x3e, (byte) 0x4b, (byte) 0xc6, (byte) 0xd2, (byte) 0x79, (byte) 0x20, (byte) 0x9a, (byte) 0xdb, (byte) 0xc0, (byte) 0xfe, (byte) 0x78, (byte) 0xcd, (byte) 0x5a, (byte) 0xf4},
		{(byte) 0x1f, (byte) 0xdd, (byte) 0xa8, (byte) 0x33, (byte) 0x88, (byte) 0x07, (byte) 0xc7, (byte) 0x31, (byte) 0xb1, (byte) 0x12, (byte) 0x10, (byte) 0x59, (byte) 0x27, (byte) 0x80, (byte) 0xec, (byte) 0x5f},
		{(byte) 0x60, (byte) 0x51, (byte) 0x7f, (byte) 0xa9, (byte) 0x19, (byte) 0xb5, (byte) 0x4a, (byte) 0x0d, (byte) 0x2d, (byte) 0xe5, (byte) 0x7a, (byte) 0x9f, (byte) 0x93, (byte) 0xc9, (byte) 0x9c, (byte) 0xef},
		{(byte) 0xa0, (byte) 0xe0, (byte) 0x3b, (byte) 0x4d, (byte) 0xae, (byte) 0x2a, (byte) 0xf5, (byte) 0xb0, (byte) 0xc8, (byte) 0xeb, (byte) 0xbb, (byte) 0x3c, (byte) 0x83, (byte) 0x53, (byte) 0x99, (byte) 0x61},
		{(byte) 0x17, (byte) 0x2b, (byte) 0x04, (byte) 0x7e, (byte) 0xba, (byte) 0x77, (byte) 0xd6, (byte) 0x26, (byte) 0xe1, (byte) 0x69, (byte) 0x14, (byte) 0x63, (byte) 0x55, (byte) 0x21, (byte) 0x0c, (byte) 0x7d}};
	private final int[] rijndaelRCon = {0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000};
	private final byte[][] rijndaelMixColumnsMatrix = {
			{(byte) 0x02, (byte) 0x03, (byte) 0x01, (byte) 0x01},
			{(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x01},
			{(byte) 0x01, (byte) 0x01, (byte) 0x02, (byte) 0x03},
			{(byte) 0x03, (byte) 0x01, (byte) 0x01, (byte) 0x02}};
	private final byte[][] rijndaelInverseMixColumnsMatrix = {
			{(byte) 0x0e, (byte) 0x0b, (byte) 0x0d, (byte) 0x09},
			{(byte) 0x09, (byte) 0x0e, (byte) 0x0b, (byte) 0x0d},
			{(byte) 0x0d, (byte) 0x09, (byte) 0x0e, (byte) 0x0b},
			{(byte) 0x0b, (byte) 0x0d, (byte) 0x09, (byte) 0x0e}};
	
	public RijndaelCipher(byte[] key, byte[] iv, String mode) throws Exception {
		super("Rijndael", key, iv, mode, 16, 11);
		if (key.length != 16) {
			throw new InvalidKeyException();
		}
	}
	
	public RijndaelCipher(byte[] key) throws Exception {
		super("Rijndael", key, null, "ECB", 16, 11);
		if (key.length != 16) {
			throw new InvalidKeyException();
		}
	}
	
	@Override
	protected byte[] encryptBlock(byte[] plaintext) {
		byte[] ciphertext = addRoundKey(plaintext, roundKeys[0]);
		for (int i = 1; i < ROUNDS-1; i++) {
			ciphertext = encryptionRound(ciphertext, i);
		}
		return addRoundKey(shiftRows(subBytes(ciphertext)), roundKeys[10]);
	}

	@Override
	protected byte[] decryptBlock(byte[] ciphertext) {
		byte[] plaintext = addRoundKey(ciphertext, roundKeys[10]);
		for (int i = 9; i > 0; i--) {
			plaintext = decryptionRound(plaintext, i);
		}
		return addRoundKey(inverseSubBytes(inverseShiftRows(plaintext)), roundKeys[0]);
	}

	@Override
	protected byte[] encryptionRound(byte[] roundBytes, int roundNumber) {
		return addRoundKey(mixColumns(shiftRows(subBytes(roundBytes))), roundKeys[roundNumber]);
	}

	@Override
	protected byte[] decryptionRound(byte[] roundBytes, int roundNumber) {
//		byte[] theReturn = roundBytes.clone();
//		theReturn = inverseShiftRows(theReturn);
//		theReturn = inverseSubBytes(theReturn);
//		theReturn = addRoundKey(theReturn, roundKeys[roundNumber]);
//		theReturn = inverseMixColumns(theReturn);
//		return theReturn;
		return inverseMixColumns(addRoundKey(inverseSubBytes(inverseShiftRows(roundBytes)), roundKeys[roundNumber]));
	}
	
	private byte[] subBytes(byte[] b) {
		byte[] subbed = new byte[16];
		for (int i = 0; i < 16; i++) {
			subbed[i] = rijndaelSBox[(b[i] >>> 4) & 0xf][b[i] & 0xf];
		}
		return subbed;
	}
	
	private byte[] inverseSubBytes(byte[] b) {
		byte[] subbed = new byte[16];
		for (int i = 0; i < 16; i++) {
			subbed[i] = rijndaelInverseSBox[(b[i] >>> 4) & 0xf][b[i] & 0xf];
		}
		return subbed;
	}
	
	private byte[] shiftRows(byte[] b) {
		byte[] shifted = b.clone();
		shifted[1] = b[5];
		shifted[2] = b[10];
		shifted[3] = b[15];
		shifted[5] = b[9];
		shifted[6] = b[14];
		shifted[7] = b[3];
		shifted[9] = b[13];
		shifted[10] = b[2];
		shifted[11] = b[7];
		shifted[13] = b[1];
		shifted[14] = b[6];
		shifted[15] = b[11];
		return shifted;
	}
	
	private byte[] inverseShiftRows(byte[] b) {
		byte[] shifted = b.clone();
		shifted[1] = b[13];
		shifted[2] = b[10];
		shifted[3] = b[7];
		shifted[5] = b[1];
		shifted[6] = b[14];
		shifted[7] = b[11];
		shifted[9] = b[5];
		shifted[10] = b[2];
		shifted[11] = b[15];
		shifted[13] = b[9];
		shifted[14] = b[6];
		shifted[15] = b[3];
		return shifted;
	}
	
	private byte[] mixColumns(byte[] b) {
		byte[] mixed = new byte[16];
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				for (int k = 0; k < 4; k++) {
					mixed[4*i + j] ^= gfMult(rijndaelMixColumnsMatrix[j][k], b[4*i + k]);
				}
			}
		}
		return mixed;
	}
	
	private byte[] inverseMixColumns(byte[] b) {
		byte[] mixed = new byte[16];
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				for (int k = 0; k < 4; k++) {
					mixed[4*i + j] ^= gfMult(rijndaelInverseMixColumnsMatrix[j][k], b[4*i + k]);
				}
			}
		}
		return mixed;
	}
		
	private byte[] addRoundKey(byte[] b, byte[] roundKey) {
		for (int i = 0; i < 16; i++) {
			b[i] ^= roundKey[i];
		}
		return b;
	}

	private byte[] subWord(byte[] b) {
		byte[] subbed = new byte[4];
		for (int i = 0; i < 4; i++) {
			subbed[i] = rijndaelSBox[(b[i] >>> 4) & 0x0f][b[i] & 0x0f];
		}
		return subbed;
	}
	
	private int g(int w, int round) {		
		return A9Utility.bytesToInt(subWord(A9Utility.intToBytes(Integer.rotateLeft(w, 8)))) ^ rijndaelRCon[round];
	}
	
	protected void makeRoundKeys() {
		roundKeys = new byte[11][16];
		int[] w = new int[44];
		int temp;
		for (int i = 0; i < 4; i++) {
			byte[] t = new byte[4];
			System.arraycopy(key, 4*i, t, 0, 4);
			w[i] = A9Utility.bytesToInt(t); 
		}
		for (int i = 4; i < 44; i++) {
			temp = w[i-1];
			if ((i % 4) == 0)
				temp = g(temp, (i/4) - 1);
			w[i] = w[i-4] ^ temp;
		}
		for (int i = 0; i < 11; i++) {
			System.arraycopy(A9Utility.intToBytes(w[4*i]), 0, roundKeys[i], 0, 4);
			System.arraycopy(A9Utility.intToBytes(w[4*i+1]), 0, roundKeys[i], 4, 4);
			System.arraycopy(A9Utility.intToBytes(w[4*i+2]), 0, roundKeys[i], 8, 4);
			System.arraycopy(A9Utility.intToBytes(w[4*i+3]), 0, roundKeys[i], 12, 4);
		}
	}
	
	public static byte gfMult(byte a, byte b) {
		byte p = 0;
		boolean doXor;
		for (int i = 0; i < 8; i++) {
			if ((a & 1) == 1)
				p ^= b;
			doXor = ((b & 0x80) == 0x80);
			b = (byte) ((b << 1) & 0xff);
			if (doXor)
				b ^= 0x1b;
			a >>>= 1;
		}
		return p;
	}

}
