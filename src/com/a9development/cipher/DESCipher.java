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

import com.a9development.A9Utility;

public class DESCipher extends BlockCipher {

	private boolean[] desKeyBits;
	private boolean[][] bitRoundKeys;

	private final int[] desKeySchedule = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};
	private final int[] desIP = {
			58, 50, 42, 34, 26, 18, 10, 2,
			60, 52, 44, 36, 28, 20, 12, 4,
			62, 54, 46, 38, 30, 22, 14, 6, 
			64, 56, 48, 40, 32, 24, 16, 8, 
			57, 49, 41, 33, 25, 17,  9, 1, 
			59, 51, 43, 35, 27, 19, 11, 3, 
			61, 53, 45, 37, 29, 21, 13, 5, 
			63, 55, 47, 39, 31, 23, 15, 7};
	private final int[] desInverseIP = {
			40, 8, 48, 16, 56, 24, 64, 32, 
			39, 7, 47, 15, 55, 23, 63, 31, 
			38, 6, 46, 14, 54, 22, 62, 30, 
			37, 5, 45, 13, 53, 21, 61, 29, 
			36, 4, 44, 12, 52, 20, 60, 28, 
			35, 3, 43, 11, 51, 19, 59, 27, 
			34, 2, 42, 10, 50, 18, 58, 26, 
			33, 1, 41,  9, 49, 17, 57, 25};
	private final int[] desE = {
			32,  1,  2,  3,  4,  5, 
			4,  5,  6,  7,  8,  9, 
			8,  9, 10, 11, 12, 13, 
			12, 13, 14, 15, 16, 17,
			16, 17, 18, 19, 20, 21, 
			20, 21, 22, 23, 24, 25, 
			24, 25, 26, 27, 28, 29, 
			28, 29, 30, 31, 32,  1};
	private final int[] desP = {
			16,  7, 20, 21, 29, 12, 28, 17, 
			1, 15, 23, 26,  5, 18, 31, 10, 
			2,  8, 24, 14, 32, 27,  3,  9, 
			19, 13, 30,  6, 22, 11,  4, 25};
	private final int[] desPC1 = {
			57, 49, 41, 33, 25, 17,  9,
			1, 58, 50, 42, 34, 26, 18,
			10,  2, 59, 51, 43, 35, 27,
			19, 11,  3, 60, 52, 44, 36,
			63, 55, 47, 39, 31, 23, 15,
			7, 62, 54, 46, 38, 30, 22,
			14,  6, 61, 53, 45, 37, 29,
			21, 13,  5, 28, 20, 12,  4};
	private final int[] desPC2 = {
			14, 17, 11, 24,  1,  5,  3, 28,
			15,  6, 21, 10, 23, 19, 12,  4,
			26,  8, 16,  7, 27, 20, 13,  2, 
			41, 52, 31, 37, 47, 55, 30, 40, 
			51, 45, 33, 48, 44, 49, 39, 56, 
			34, 53, 46, 42, 50, 36, 29, 32};
	private final int[][][] desSBoxes = {{{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
		{0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
		{4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
		{15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}},
		{{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
			{3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
			{0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
			{13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}},
			{{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
				{13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
				{13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
				{1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}},
				{{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
					{13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
					{10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
					{3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}},
					{{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
						{14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
						{4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
						{11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}},
						{{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
							{10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
							{9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
							{4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}},
							{{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
								{13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
								{1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
								{6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}},
								{{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
									{1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
									{7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
									{2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}}};


	public DESCipher(byte[] key, byte[] iv, String mode) throws Exception {
		super("DES", key, iv, mode, 8, 16);
		if (key.length != 8) {
			throw new InvalidKeyException();
		}
//		if (key.length != 8) {
//			throw new Exception("Invalid key length " + key.length);
//		} else if (!mode.equals("ECB") || !mode.equals("CBC") || !mode.equals("CFB") || !mode.equals("OFB") || !mode.equals("CTR")) {
//			throw new Exception("Invalid mode " + mode);
//		} else if (iv.length != 8 && !mode.equals("ECB")) {
//			throw new Exception("Invalid iv length " + iv.length);
//		} else {
//			this.algorithm = "DES";
//			this.blockSize = 8;
//			this.numberOfRounds = 16;
//			this.mode = mode;
//			this.key = key;
//			this.iv = iv;
//			
//			// create the 64b key from the 8B key
//			desKeyBits = new boolean[64];
//			for (int i = 0; i < 8; i++) {
//				System.arraycopy(A9Utility.byteToBits(key[i]), 0, desKeyBits, i*8, 8);
//			}
//		}
	}

	public DESCipher(byte[] key) throws Exception {
		super("DES", key, null, "ECB", 8, 16);
//		if (key.length != 8) {
//			throw new Exception("Invalid key length " + key.length);
//		} else {
//			this.algorithm = "DES";
//			this.blockSize = 8;
//			this.numberOfRounds = 16;
//			this.mode = "ECB";
//			this.key = key;
//			this.iv = new byte[blockSize];
//			
//			desKeyBits = new boolean[64];
//			for (int i = 0; i < 8; i++) {
//				System.arraycopy(A9Utility.byteToBits(key[i]), 0, desKeyBits, i*8, 8);
//			}
//		}
	}

	@Override
	protected byte[] decryptBlock(byte[] ciphertext) {
		byte[] plaintext = new byte[ciphertext.length];
		boolean[] plaintextBits = new boolean[64];
		makeRoundKeys();
		for (int i = 0; i < 8; i++) {
			System.arraycopy(A9Utility.byteToBits(ciphertext[i]), 0, plaintextBits, i*8, 8);
		}

		// IP
		plaintextBits = doInitialPermutation(plaintextBits);

		// Rounds
		byte[] roundBytes = new byte[8];
		roundBytes = A9Utility.bitsTo8Bytes(plaintextBits);
		for (int i = ROUNDS; i > 0; i--) {
			roundBytes = encryptionRound(roundBytes, i-1);
		}
		for (int i = 0; i < 8; i++) {
			System.arraycopy(A9Utility.byteToBits(roundBytes[i]), 0, plaintextBits, 8*i, 8);
		}

		// Swap 32
		boolean[] tmp = plaintextBits.clone();
		System.arraycopy(tmp, 0, plaintextBits, 32, 32);
		System.arraycopy(tmp, 32, plaintextBits, 0, 32);

		// Inverse IP
		plaintextBits = doInverseInitialPermutation(plaintextBits);

		plaintext = A9Utility.bitsTo8Bytes(plaintextBits);

		return plaintext;
	}

	@Override
	protected byte[] encryptBlock(byte[] plaintext) {
		byte[] ciphertext = new byte[plaintext.length];
		boolean[] ciphertextBits = new boolean[64];
		makeRoundKeys();
		for (int i = 0; i < 8; i++) {
			System.arraycopy(A9Utility.byteToBits(plaintext[i]), 0, ciphertextBits, i*8, 8);
		}

		// IP
		ciphertextBits = doInitialPermutation(ciphertextBits);

		// Rounds
		byte[] roundBytes = new byte[8];
		roundBytes = A9Utility.bitsTo8Bytes(ciphertextBits);
		for (int i = 0; i < ROUNDS; i++) {
			roundBytes = encryptionRound(roundBytes, i);
		}
		for (int i = 0; i < 8; i++) {
			System.arraycopy(A9Utility.byteToBits(roundBytes[i]), 0, ciphertextBits, 8*i, 8);
		}

		// Swap 32
		boolean[] tmp = ciphertextBits.clone();
		System.arraycopy(tmp, 0, ciphertextBits, 32, 32);
		System.arraycopy(tmp, 32, ciphertextBits, 0, 32);

		// Inverse IP
		ciphertextBits = doInverseInitialPermutation(ciphertextBits);

		ciphertext = A9Utility.bitsTo8Bytes(ciphertextBits);

		return ciphertext;
	}

	@Override
	protected byte[] encryptionRound(byte[] roundBytes, int roundNumber) {
		boolean[] left = new boolean[32], right = new boolean[32], finished = new boolean[64];
		for (int i = 0; i < 4; i++) {
			System.arraycopy(A9Utility.byteToBits(roundBytes[i]), 0, left, i*8, 8);
			System.arraycopy(A9Utility.byteToBits(roundBytes[i+4]), 0, right, i*8, 8);
		}

		System.arraycopy(right, 0, finished, 0, 32);
		boolean[] tmp = F(right, bitRoundKeys[roundNumber]);
		for (int j = 0; j < 32; j++) {
			right[j] = (tmp[j] ^ left[j]);
		}
		System.arraycopy(right, 0, finished, 32, 32);

		return A9Utility.bitsTo8Bytes(finished);
	}

	@Override
	protected byte[] decryptionRound(byte[] roundBytes, int roundNumber) {
		return encryptionRound(roundBytes, roundNumber);
	}

	@Override
	protected void makeRoundKeys() {
		bitRoundKeys = new boolean[16][48];
		desKeyBits = new boolean[64];
		boolean[][] desKey56 = new boolean[17][56];
		boolean[][] desC = new boolean[17][28];
		boolean[][] desD = new boolean[17][28];

		for (int i = 0; i < 8; i++) {
			System.arraycopy(A9Utility.byteToBits(key[i]), 0, desKeyBits, 8*i, 8);
		}
		
		for (int i = 0; i < 56; i++) {
			desKey56[0][i] = desKeyBits[desPC1[i]-1]; 
		}

		System.arraycopy(desKey56[0], 0, desC[0], 0, 28);
		System.arraycopy(desKey56[0], 28, desD[0], 0, 28);

		for (int i = 1; i < 17; i++) {
			for (int j = 0; j < 28; j++) {
				desKey56[i][j] = desC[i][j] = desC[i-1][(j+desKeySchedule[i-1])%28];
				desKey56[i][28+j] = desD[i][j] = desD[i-1][(j+desKeySchedule[i-1])%28];
			}
		}

		for (int i = 0; i < 16; i++) {
			for (int j = 0; j < 48; j++) {
				bitRoundKeys[i][j] = desKey56[i+1][desPC2[j]-1];
			}
		}
	}

	private boolean[] doInitialPermutation(boolean[] toPermute)  {
		boolean[] permuted = new boolean[64];
		for (int i = 0; i < 64; i++) {
			permuted[i] = toPermute[desIP[i]-1];
		}
		return permuted;
	}

	private boolean[] F(boolean[] input, boolean[] desSubKeyI) {
		boolean[] tmp = new boolean[48];
		for (int i = 0; i < 48; i++) {
			tmp[i] = (Expand(input)[i] != desSubKeyI[i]);
		}
		boolean[] postS = SBoxMath(tmp);
		return permutationP(postS);
	}

	private boolean[] Expand(boolean[] toExpand) {
		boolean[] tmp = new boolean[48];
		for (int i = 0; i < 48; i++) {
			tmp[i] = toExpand[desE[i]-1];
		}
		return tmp;
	}

	private boolean[] SBoxMath(boolean[] theSBoxInput) {
		int[] tmp = new int[8];
		for (int i = 0; i < 8; i++) {
			int r = 2 * ((theSBoxInput[(6 * i) + 0]) ? 1 : 0)
			+ ((theSBoxInput[(6 * i) + 5]) ? 1 : 0);
			int c = 8 * ((theSBoxInput[(6 * i) + 1]) ? 1 : 0) + 4
			* ((theSBoxInput[(6 * i) + 2]) ? 1 : 0) + 2
			* ((theSBoxInput[(6 * i) + 3]) ? 1 : 0)
			+ ((theSBoxInput[(6 * i) + 4]) ? 1 : 0);
			tmp[i] = desSBoxes[i][r][c];
		}
		boolean[] postS = new boolean[32];
		for (int i = 0; i < 8; i++) {
			postS[(4 * i)] = ((tmp[i] & 8) != 0);
			postS[(4 * i) + 1] = ((tmp[i] & 4) != 0);
			postS[(4 * i) + 2] = ((tmp[i] & 2) != 0);
			postS[(4 * i) + 3] = ((tmp[i] & 1) != 0);
		}
		return postS;
	}

	private boolean[] permutationP(boolean[] toPermute) {
		boolean[] permuted = new boolean[32];
		for (int i = 0; i < 32; i++) {
			permuted[i] = toPermute[desP[i]-1];
		}
		return permuted;
	}

	private boolean[] doInverseInitialPermutation(boolean[] toPermute) {
		boolean[] permuted = new boolean[64];
		for (int i = 0; i < 64; i++) {
			permuted[i] = toPermute[desInverseIP[i]-1];
		}
		return permuted;
	}

}
