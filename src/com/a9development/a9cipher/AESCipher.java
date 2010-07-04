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

/**
 * The textbook being used gave this example:<br>
 * Plaintext:  0123456789abcdeffedcba9876543210<br>
 * Key:        0f1571c947d9e8590cb7add6af7f6798<br>
 * Ciphertext: ff0b844a0853bf7c6934ab4364148fb9
 * 
 * @author Daniel Kotowski
 * @version 1.0.0
 */

public class AESCipher implements Cloneable {
	private byte[] aesKey;
	
	private static final byte[][] aesSBox = {
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
	private static final byte[][] aesInverseSBox = {
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
	private byte[] aesRcon = {(byte) 0x01, (byte) 0x02, (byte) 0x04, (byte) 0x08, (byte) 0x10, (byte) 0x20, (byte) 0x40, (byte) 0x80, (byte) 0x1b, (byte) 0x36};
	
	public AESCipher(byte[] key) throws Exception {
		if (key.length != 16) {
			// Currently only supports 128-bit keys. Will be expanded in a future version
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
			byte[][] ctMatrix = new byte[4][4];
			byte[][] ptMatrix = new byte[4][4];
			for (int i = 0; i < 4; i++) {
				ptMatrix[i][0] = plaintext[4*i];
				ptMatrix[i][1] = plaintext[4*i + 1];
				ptMatrix[i][2] = plaintext[4*i + 2];
				ptMatrix[i][3] = plaintext[4*i + 3];
			}
			byte[][][] aesRKeys = aesMakeRoundKeys(aesKey);
			ctMatrix = aesAddRoundKey(ptMatrix, aesRKeys[0]);
			for (int i = 1; i < 10; i++) {
//				ctMatrix = aesAddRoundKey(aesMixColumns(aesShiftRows(aesSubBytes(ctMatrix))), aesRKeys[i]);
				ctMatrix = aesSubBytes(ctMatrix);
				ctMatrix = aesShiftRows(ctMatrix);
				ctMatrix = aesMixColumns(ctMatrix);
				ctMatrix = aesAddRoundKey(ctMatrix, aesRKeys[i]);
			}
			ctMatrix = aesAddRoundKey(aesShiftRows(aesSubBytes(ctMatrix)), aesRKeys[10]);
			for (int i = 0; i < 4; i++) {
				ciphertext[i] = ctMatrix[i][0];
				ciphertext[i+1] = ctMatrix[i][1];
				ciphertext[i+2] = ctMatrix[i][2];
				ciphertext[i+3] = ctMatrix[i][3];
			}
			return ciphertext;
		}
	}
	
	public byte[] decrypt(byte[] ciphertext) throws Exception {
		if (ciphertext.length != 16) {
			throw new Exception("ciphertext must be 16 bytes long");
		} else {
			byte[] plaintext = new byte[16];
			byte[][] ptMatrix = new byte[4][4];
			byte[][] ctMatrix = new byte[4][4];
			for (int i = 0; i < 4; i++) {
				ctMatrix[i][0] = ciphertext[4*i];
				ctMatrix[i][1] = ciphertext[4*i+1];
				ctMatrix[i][2] = ciphertext[4*i+2];
				ctMatrix[i][3] = ciphertext[4*i+3];
			}
			byte[][][] aesRKeys = aesMakeRoundKeys(aesKey);
			ptMatrix = aesAddRoundKey(ctMatrix, aesRKeys[10]);
			for (int i = 9; i > 0; i--) {
				ptMatrix = aesInverseMixColumns(aesAddRoundKey(aesInverseSubBytes(aesInverseShiftRows(ptMatrix)), aesRKeys[i]));
			}
			ptMatrix = aesAddRoundKey(aesInverseSubBytes(aesInverseShiftRows(ptMatrix)), aesRKeys[0]);
			for (int i = 0; i < 4; i++) {
				plaintext[i] = ptMatrix[i][0];
				plaintext[i+1] = ptMatrix[i][1];
				plaintext[i+2] = ptMatrix[i][2];
				plaintext[i+3] = ptMatrix[i][3];
			}
			return plaintext;
		}
	}

	private byte[][] aesSubBytes (byte[][] B) throws Exception {
		if (B.length != 4 || B[0].length != 4) {
			throw new Exception("B must be 4x4 bytes");
		} else {
			byte[][] subbed = new byte[4][4];
			for (int i = 0; i < 4; i++) {
				for (int j = 0; j < 4; j++) {
					//TODO how is it even possible for r and c to be negative???
					int r = B[i][j] >> 4;
					int c = B[i][j] % 16;
					subbed[i][j] = aesSBox[r][c];
				}
			}
			return subbed;
		}
	}
	
	private byte[][] aesInverseSubBytes (byte[][] B) throws Exception {
		if (B.length != 4 || B[0].length != 4) {
			throw new Exception("B must be 4x4 bytes");
		} else {
			byte[][] subbed = new byte[4][4];
			for (int i = 0; i < 4; i++) {
				for (int j = 0; j < 4; j++) {
					subbed[i][j] = aesInverseSBox[B[i][j] >> 4][B[i][j] % 16];
				}
			}
			return subbed;
		}
	}
	
	private byte[][] aesShiftRows (byte[][] B) throws Exception {
		if (B.length != 4 || B[0].length != 4) {
			throw new Exception("B must be 4x4 bytes");
		} else {
			byte[][] shifted = new byte[4][4];
			for (int i = 0; i < 4; i++) {
				for (int j = 0; j < 4; j++) {
					shifted[i][j] = B[i][(j+4-i)%4];
				}
			}
			return shifted;
		}
	}
	
	private byte[][] aesInverseShiftRows (byte[][] B) throws Exception {
		if (B.length != 4 || B[0].length != 4) {
			throw new Exception("B must be 4x4 bytes");
		} else {
			byte[][] shifted = new byte[4][4];
			for (int i = 0; i < 4; i++) {
				for (int j = 0; j < 4; j++) {
					shifted[i][j] = B[i][(j+i)%4];
				}
			}
			return shifted;
		}
	}
	
	private byte[][] aesMixColumns (byte[][] B) throws Exception {
		if (B.length != 4 || B[0].length != 4) {
			throw new Exception("B must be 4x4 bytes");
		} else {
			byte[][] mixed = new byte[4][4];
			for (int j = 0; j < 4; j++) {
				mixed[0][j] = (byte) ((2 * B[0][j]) ^ (3 * B[1][j]) ^ B[2][j] ^ B[3][j]);
				mixed[1][j] = (byte) ((2 * B[1][j]) ^ (3 * B[2][j]) ^ B[3][j] ^ B[0][j]);
				mixed[2][j] = (byte) ((2 * B[2][j]) ^ (3 * B[3][j]) ^ B[0][j] ^ B[1][j]);
				mixed[3][j] = (byte) ((2 * B[3][j]) ^ (3 * B[0][j]) ^ B[1][j] ^ B[2][j]);
			}
			return mixed;
		}
	}
	
	private byte[][] aesInverseMixColumns (byte[][] B) throws Exception {
		if (B.length != 4 || B[0].length != 4) {
			throw new Exception("B must be 4x4 bytes");
		} else {
			byte[][] mixed = new byte[4][4];
			for (int j = 0; j < 4; j++) {
				mixed[0][j] = (byte) (((byte) 0x0e * B[0][j]) ^ ((byte) 0x0b * B[1][j]) ^ ((byte) 0x0d * B[2][j]) ^ ((byte) 0x09 * B[3][j]));
				mixed[1][j] = (byte) (((byte) 0x0e * B[1][j]) ^ ((byte) 0x0b * B[2][j]) ^ ((byte) 0x0d * B[3][j]) ^ ((byte) 0x09 * B[0][j]));
				mixed[2][j] = (byte) (((byte) 0x0e * B[2][j]) ^ ((byte) 0x0b * B[3][j]) ^ ((byte) 0x0d * B[0][j]) ^ ((byte) 0x09 * B[1][j]));
				mixed[3][j] = (byte) (((byte) 0x0e * B[3][j]) ^ ((byte) 0x0b * B[0][j]) ^ ((byte) 0x0d * B[1][j]) ^ ((byte) 0x09 * B[2][j]));
			}
			return mixed;
		}
	}
	
	private byte[][] aesAddRoundKey (byte[][] B, byte[][] roundKey) throws Exception {
		if (B.length != 4 || B[0].length != 4) {
			throw new Exception("B must be 4x4 bytes");
		} else if (roundKey.length != 4 || roundKey[0].length != 4) {
			throw new Exception("roundKey must be 4x4 bytes");
		} else {
			byte[][] keyed = new byte[4][4];
			for (int i = 0; i < 4; i++) {
				for (int j = 0; j < 4; j++) {
					keyed[i][j] = (byte) (B[i][j] ^ roundKey[i][j]);
				}
			}
			return keyed;
		}
	}
	
	private byte[] aesSubWord(byte[] W) throws Exception {
		if (W.length != 4) {
			throw new Exception("W must be 4 bytes");
		} else {
			byte[] subbed = new byte[4];
			for (int i = 0; i < 4; i++) {
				subbed[i] = aesSBox[W[i] >> 4][W[i] % 16];
			}
			return subbed;
		}
	}
	
	private byte[] aesRotWord(byte[] W) throws Exception {
		if (W.length != 4) {
			throw new Exception("W must be 4 bytes");
		} else {
			byte[] rotted = new byte[4];
			rotted[0] = W[1];
			rotted[1] = W[2];
			rotted[2] = W[3];
			rotted[3] = W[0];
			return rotted;
		}
	}
	
	private byte[][][] aesMakeRoundKeys (byte[] key) throws Exception {
		if (key.length != 16) {
			throw new Exception("key must be 16 bytes long");
		} else {
			byte[][][] aesRoundKeys = new byte[11][4][4];
			for (int i = 0; i < 4; i++) {
				for (int j = 0; j < 4; j++) {
					aesRoundKeys[0][i][j] = key[4*i + j];
				}
			}
			byte[] temp = new byte[4];
			for (int i = 4; i < 11; i++) {
				for (int j = 0; j < 4; j++) {
					temp = aesRoundKeys[i-1][j];
					if (j == 0) {
						temp[0] = (byte) ((aesSubWord(aesRotWord(temp))[0]) ^ aesRcon[i/4]);
						temp[1] = (byte) (aesSubWord(aesRotWord(temp))[1]);
						temp[2] = (byte) (aesSubWord(aesRotWord(temp))[2]);
						temp[3] = (byte) (aesSubWord(aesRotWord(temp))[3]);
					}
					for (int k = 0; k < 4; k++) {
						aesRoundKeys[i][j][k] = (byte) (aesRoundKeys[i-1][j][k] ^ temp[k]);
					}
				}
			}
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