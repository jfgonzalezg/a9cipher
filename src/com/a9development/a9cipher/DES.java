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
 * A class for working with the Data Encryption Standard, more commonly known
 * as DES. It will accept a String, byte array, or boolean array as input to
 * the constructor for the input text and key. Currently all inputs are
 * restricted to the normal DES block size of 64 bits, 8 bytes, or 16 hex
 * digits, but this will be expanded in future versions for to support larger
 * and smaller text and smaller keys, by means of padding to the next 8 bytes.
 * 
 * @author Daniel Kotowski
 * @version 1.0.0
 * @see http://csrc.nist.gov/publications/fips/fips46-3.pdf
 */
public class DES implements Cloneable {
	private String desPlainTextString;
	private String desCipherTextString;
	private String desKeyString;
	private byte[] desPlainTextBytes;
	private byte[] desCipherTextBytes;
	private byte[] desKeyBytes;
	private boolean[] desPlainTextBits;
	private boolean[] desTempTextBits;
	private boolean[] desCipherTextBits;
	private boolean[] desKeyBits;
	private boolean[][] desKey56;
	private boolean[][] desSubKeys;
	private boolean[][] desLeftHalf;
	private boolean[][] desRightHalf;
	private boolean[][] desC;
	private boolean[][] desD;
	private boolean unencrypted;
		
	private int[] desKeySchedule = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};
	private int[] desIP = {
			58, 50, 42, 34, 26, 18, 10, 2,
			60, 52, 44, 36, 28, 20, 12, 4,
			62, 54, 46, 38, 30, 22, 14, 6, 
			64, 56, 48, 40, 32, 24, 16, 8, 
			57, 49, 41, 33, 25, 17,  9, 1, 
			59, 51, 43, 35, 27, 19, 11, 3, 
			61, 53, 45, 37, 29, 21, 13, 5, 
			63, 55, 47, 39, 31, 23, 15, 7};
	private int[] desInverseIP = {
			40, 8, 48, 16, 56, 24, 64, 32, 
			39, 7, 47, 15, 55, 23, 63, 31, 
			38, 6, 46, 14, 54, 22, 62, 30, 
			37, 5, 45, 13, 53, 21, 61, 29, 
			36, 4, 44, 12, 52, 20, 60, 28, 
			35, 3, 43, 11, 51, 19, 59, 27, 
			34, 2, 42, 10, 50, 18, 58, 26, 
			33, 1, 41,  9, 49, 17, 57, 25};
	private int[] desE = {
			32,  1,  2,  3,  4,  5, 
			 4,  5,  6,  7,  8,  9, 
			 8,  9, 10, 11, 12, 13, 
			12, 13, 14, 15, 16, 17,
			16, 17, 18, 19, 20, 21, 
			20, 21, 22, 23, 24, 25, 
			24, 25, 26, 27, 28, 29, 
			28, 29, 30, 31, 32,  1};
	private int[] desP = {
			16,  7, 20, 21, 29, 12, 28, 17, 
			 1, 15, 23, 26,  5, 18, 31, 10, 
			 2,  8, 24, 14, 32, 27,  3,  9, 
			19, 13, 30,  6, 22, 11,  4, 25};
	private int[] desPC1 = {
			57, 49, 41, 33, 25, 17,  9,
			 1, 58, 50, 42, 34, 26, 18,
			10,  2, 59, 51, 43, 35, 27,
			19, 11,  3, 60, 52, 44, 36,
			63, 55, 47, 39, 31, 23, 15,
			 7, 62, 54, 46, 38, 30, 22,
			14,  6, 61, 53, 45, 37, 29,
			21, 13,  5, 28, 20, 12,  4};
	private int[] desPC2 = {
			14, 17, 11, 24,  1,  5,  3, 28,
			15,  6, 21, 10, 23, 19, 12,  4,
			26,  8, 16,  7, 27, 20, 13,  2, 
			41, 52, 31, 37, 47, 55, 30, 40, 
			51, 45, 33, 48, 44, 49, 39, 56, 
			34, 53, 46, 42, 50, 36, 29, 32};
	private int[][][] desSBoxes = {{{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
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

	/**
	 * Constructor
	 * 
	 * @param text			8 byte big-endian plaintext
	 * @param key			8 byte big-endian encryption key
	 * @throws Exception	if the plaintext or key are not the right size
	 * 						(8 bytes)
	 */
	public DES(byte[] text, byte[] key) throws Exception {
		// TODO rewrite to allow for plaintext of length other than 8 bytes (pad to nextt 8 bytes)
		// TODO rewrite to allow for keys of length less than 8 bytes (pad to 8 - do not allow greater than 8 bytes)
		// TODO initialize string, byte, and boolean arrays for PT, K, and CT
		
		if (text.length != 8) {
			throw new Exception("Plain text must be 8 bytes long");
		} else if (key.length != 8) {
			throw new Exception("Key must be 8 bytes long");
		} else {
			desPlainTextBytes = text.clone();
			desKeyBytes = key.clone();
			desCipherTextBytes = new byte[8];
			desPlainTextBits = new boolean[64];
			desKeyBits = new boolean[64];
			unencrypted = true;
			
			boolean[] tmpDesPlainText = new boolean[8];
			boolean[] tmpDesKey = new boolean[8];
			for (int i = 0; i < 8; i++) {
				tmpDesPlainText = convertToBits(desPlainTextBytes[i]);
				tmpDesKey = convertToBits(desKeyBytes[i]);
				for (int j = 0; j < 8; j++) {
					desPlainTextBits[(8*i)+j] = tmpDesPlainText[j];
					desKeyBits[(8*i)+j] = tmpDesKey[j];
				}
			}
			desCipherTextBits = desPlainTextBits.clone();
			desTempTextBits = desPlainTextBits.clone();
		}
	}
	
	/**
	 * Constructor
	 * 
	 * @param text			64 bit plaintext as big-endian boolean array
	 * @param key			64 bit encryption key as big-endian boolean array
	 * @throws Exception	if the plaintext or key are not the right size
	 * 						(64 bits)
	 */
	public DES(boolean[] text, boolean[] key) throws Exception {
		// TODO rewrite to allow for plaintext of length other than 64 bits (pad to next 64 bits)
		// TODO rewrite to allow for keys of length less than 64 bits (pad to 64 - do not allow greater than 64 bits)
		// TODO initialize string, byte, and boolean arrays for PT, K, and CT
		
		if (text.length != 64) {
			throw new Exception("Plain text must be 64 bits");
		} else if (key.length != 64) {
			throw new Exception("Key must be 64 bits");
		} else {
			desPlainTextBits = text.clone();
			desKeyBits = key.clone();
			desCipherTextBits = desPlainTextBits.clone();
			desTempTextBits = desPlainTextBits.clone();
			desCipherTextBytes = new byte[8];
			unencrypted = true;
		}
	}
	
	/**
	 * Constructor
	 * 
	 * @param text			8 byte big-endian text,
	 * 						can be plaintext or ciphertext
	 * @param key			8 byte big-endian encryption key
	 * @param encrypted		is the text already encrypted?
	 * @throws Exception	if the text or key are not the right size
	 * 						(8 bytes)
	 */
	public DES(byte[] text, byte[] key, boolean encrypted) throws Exception {
		// TODO rewrite to allow for plaintext of length other than 64 bits (pad to next 64 bits)
		// TODO rewrite to allow for keys of length less than 64 bits (pad to 64 - do not allow greater than 64 bits)
		// TODO initialize string, byte, and boolean arrays for PT, K, and CT
		
		if (text.length != 8) {
			throw new Exception("Plain text must be 8 bytes long");
		} else if (key.length != 8) {
			throw new Exception("Key must be 8 bytes long");
		} else {
			if (!encrypted) {
				desPlainTextBytes = text.clone();
				desKeyBytes = key.clone();
				desCipherTextBytes = new byte[8];
				desPlainTextBits = new boolean[64];
				desKeyBits = new boolean[64];
				unencrypted = true;
				
				boolean[] tmpDesPlainText = new boolean[8];
				boolean[] tmpDesKey = new boolean[8];
				for (int i = 0; i < 8; i++) {
					tmpDesPlainText = convertToBits(desPlainTextBytes[i]);
					tmpDesKey = convertToBits(desKeyBytes[i]);
					for (int j = 0; j < 8; j++) {
						desPlainTextBits[(8*i)+j] = tmpDesPlainText[j];
						desKeyBits[(8*i)+j] = tmpDesKey[j];
					}
				}
				desCipherTextBits = desPlainTextBits.clone();
				desTempTextBits = desPlainTextBits.clone();
			} else {
				desCipherTextBytes = text.clone();
				desKeyBytes = key.clone();
				desPlainTextBytes = new byte[8];
				desCipherTextBits = new boolean[64];
				desKeyBits = new boolean[64];
				unencrypted = false;
				
				boolean[] tmpDesCipherText = new boolean[8];
				boolean[] tmpDesKey = new boolean[8];
				for (int i = 0; i < 8; i++) {
					tmpDesCipherText = convertToBits(desCipherTextBytes[i]);
					tmpDesKey = convertToBits(desKeyBytes[i]);
					for (int j = 0; j < 8; j++) {
						desCipherTextBits[(8*i)+j] = tmpDesCipherText[j];
						desKeyBits[(8*i)+j] = tmpDesKey[j];
					}
				}
				desPlainTextBits = desCipherTextBits.clone();
				desTempTextBits = desCipherTextBits.clone();
			}
		}
	}
	
	/**
	 * Constructor
	 * 
	 * @param text			64 bit text as big-endian boolean array
	 * @param key			64 bit encryption key as big-endian boolean array
	 * @param encrypted		is the text already encrypted?
	 * @throws Exception	if the text or key are not the right size
	 * 						(64 bits)
	 */
	public DES(boolean[] text, boolean[] key, boolean encrypted) throws Exception {
		// TODO rewrite to allow for plaintext of length other than 64 bits (pad to next 64 bits)
		// TODO rewrite to allow for keys of length less than 64 bits (pad to 64 - do not allow greater than 64 bits)
		// TODO initialize string, byte, and boolean arrays for PT, K, and CT
		
		if (text.length != 64) {
			throw new Exception("Plain text must be 64 bits long");
		} else if (key.length != 64) {
			throw new Exception("Key must be 64 bits long");
		} else {
			if (!encrypted) {
				desPlainTextBits = text.clone();
				desKeyBits = key.clone();
				desCipherTextBits = desPlainTextBits.clone();
				desTempTextBits = desPlainTextBits.clone();
				desPlainTextBytes = new byte[8];
				desCipherTextBytes = new byte[8];
				unencrypted = true;
			} else {
				desCipherTextBits = text.clone();
				desKeyBits = key.clone();
				desPlainTextBits = desCipherTextBits.clone();
				desTempTextBits = desCipherTextBits.clone();
				desPlainTextBytes = new byte[8];
				desCipherTextBytes = new byte[8];
				unencrypted = true;
			}
		}
	}
	
	/**
	 * Constructor
	 * 
	 * @param text			plaintext as string
	 * 						must be hex representation
	 * @param key			key as string, 
	 * 						must be hex representation
	 * @throws Exception	if text or key are no the right size
	 * 						(16 characters)
	 */
	public DES(String text, String key) throws Exception {
		// TODO initialize from strings
	}
	
	/**
	 * Constructor 
	 * @param text			text as string, can be plaintext or ciphertext,
	 * 						must be hex representation
	 * @param key			key as string,
	 * 						must be hex representation
	 * @param encrypted		is the text already encrypted?
	 * @throws Exception	if the text or key are not the right size
	 * 						(16 characters)
	 */
	public DES(String text, String key, boolean encrypted) throws Exception {
		// TODO initialize from strings
	}
	
	/**
	 * Encrypts the stored plaintext using the DES algorithm
	 * 
	 * @throws Exception
	 */
	public void Encrypt() throws Exception {
		if (unencrypted) {
			try {
				desTempTextBits = doInitialPermutation(desPlainTextBits);
			} catch (Exception e) {
				throw e;
			}
			makeSubKeys();
			try {
				desTempTextBits = doEncryptionRounds(desTempTextBits);
			} catch (Exception e) {
				throw e;
			}
			try {
				desTempTextBits = doInverseInitialPermutation(desTempTextBits);
			} catch (Exception e) {
				throw e;
			}
			try {
				desCipherTextBits = desTempTextBits;
			} catch (Exception e) {
				throw e;
			}
			try {
				buildCipherText();
			} catch (Exception e) {
				throw e;
			}
		}
	}
	
	/**
	 * Decrypts the stored ciphertext using the DES algorithm
	 * 
	 * @throws Exception
	 */
	public void Decrypt() throws Exception {
		if (!unencrypted) {
			try {
				desTempTextBits = doInitialPermutation(desCipherTextBits);
			} catch (Exception e) {
				throw e;
			}
			makeSubKeys();
			try {
				desTempTextBits = doDecryptionRounds(desTempTextBits);
			} catch (Exception e) {
				throw e;
			}
			try {
				desTempTextBits = doInverseInitialPermutation(desTempTextBits);
			} catch (Exception e) {
				throw e;
			}
			try {
				desPlainTextBits = desTempTextBits;
			} catch (Exception e) {
				throw e;
			}
			try {
				buildPlainText();
			} catch (Exception e) {
				throw e;
			}
		}
	}

	/**
	 * Takes the stored ciphertext bits and builds the ciphertext string and
	 * byte array
	 */
	private void buildCipherText() {
		for (int i = 0; i < 8; i++) {
			for (int j = 0; j < 8; j++) {
				desCipherTextBytes[i] += ((desCipherTextBits[(8*i)+j])?1:0) * Math.pow(2, 7-j);
			}
		}
		// TODO build the ciphertext string
	}
	
	/**
	 * Takes the stored plaintext bits and builds the plaintext string and
	 * byte array
	 */
	private void buildPlainText() {
		for (int i = 0; i < 8; i++) {
			for (int j = 0; j < 8; j++) {
				desPlainTextBytes[i] += ((desPlainTextBits[(8*i)+j])?1:0) * Math.pow(2, 7-j);
			}
		}
		// TODO build the plaintext string
	}

	/**
	 * Converts a byte into a big-endian boolean array
	 * @param B		the byte to be converted
	 * @return		a big-endian boolean array representing the bits of byte B
	 */
	private boolean[] convertToBits(byte B) {
		boolean[] bits = new boolean[8];
		for (int i = 0; i < 8; i++) {
			bits[7-i] = ((B & (1 << i)) != 0);
		}
		return bits;
	}
		
	/**
	 * Permutes a big-endian bit array using the DES Initial Permutation
	 * 
	 * @param toPermute		bit array to be permuted
	 * @return				permuted bit array
	 * @throws Exception	if the array input is not 64 bits
	 */
	private boolean[] doInitialPermutation(boolean[] toPermute) throws Exception {
		if (toPermute.length < 64) {
			throw new Exception("Cannot do Initial Permutation on less than 64 bits");
		} else if (toPermute.length > 64) {
			throw new Exception("Cannot do Initial Permutation on more than 64 bits");
		} else {
			boolean[] permuted = new boolean[64];
			for (int i = 0; i < 64; i++) {
				permuted[i] = toPermute[desIP[i]-1];
			}
			return permuted;
		}
	}
	
	/**
	 * Permutes a big-endian bit array using the DES Inverse Initial
	 * Permutation
	 * 
	 * @param toPermute		bit array to be permuted
	 * @return				permuted bit array
	 * @throws Exception	if the array input is not 64 bits
	 */
	private boolean[] doInverseInitialPermutation(boolean[] toPermute) throws Exception {
		if (toPermute.length < 64) {
			throw new Exception("Cannot do Initial Permutation on less than 64 bits");
		} else if (toPermute.length > 64) {
			throw new Exception("Cannot do Initial Permutation on more than 64 bits");
		} else {
			boolean[] permuted = new boolean[64];
			for (int i = 0; i < 64; i++) {
				permuted[i] = toPermute[desInverseIP[i]-1];
			}
			return permuted;
		}
	}
	
	/**
	 * Puts the intermediate text through all 16 DES encryption rounds
	 * 
	 * @param doRoundsOnThis	the bit array that the rounds are done on
	 * @return					the bit array after the rounds have been done
	 * @throws Exception		if the input array is not 64 bits
	 */
	private boolean[] doEncryptionRounds(boolean[] doRoundsOnThis) throws Exception {
		// TODO Rename doRoundsOnThis to something more meaningful

		if (doRoundsOnThis.length != 64) {
			throw new Exception("doRoundOnThis must be 64 bits");
		} else {
			// TODO Rename theRoundsAreDone to something more meaningful
			boolean[] theRoundsAreDone = new boolean[64];
			desLeftHalf = new boolean[18][32];
			desRightHalf = new boolean[18][32];

			for (int i = 0; i < 32; i++) {
				desLeftHalf[0][i] = doRoundsOnThis[i];
				desRightHalf[0][i] = doRoundsOnThis[32+i];
			}
		
			for (int i = 1; i < 17; i++) {
				desLeftHalf[i] = desRightHalf[i-1];
				for (int j = 0; j < 32; j++) {
					desRightHalf[i][j] = (F(desRightHalf[i-1], desSubKeys[i-1])[j] != desLeftHalf[i-1][j]);
				}
			}
		
			desLeftHalf[17] = desRightHalf[16].clone();
			desRightHalf[17] = desLeftHalf[16].clone();
			for (int i = 0; i < 32; i++) {
				theRoundsAreDone[i] = desLeftHalf[17][i];
				theRoundsAreDone[i+32] = desRightHalf[17][i];
			}
			return theRoundsAreDone;
		}
	}

	/**
	 * Puts the intermediate text through all 16 DES decryption rounds
	 * 
	 * @param doRoundsOnThis	the bit array that the rounds are done on
	 * @return					the bit array after the rounds have been done
	 * @throws Exception		if the input array is not 64 bits
	 */
	private boolean[] doDecryptionRounds(boolean[] doRoundsOnThis) throws Exception {
		// TODO Rename doRoundsOnThis to something more meaningful

		if (doRoundsOnThis.length != 64) {
			throw new Exception("doRoundOnThis must be 64 bits");
		} else {
			// TODO Rename theRoundsAreDone to something more meaningful
			boolean[] theRoundsAreDone = new boolean[64];
			desLeftHalf = new boolean[18][32];
			desRightHalf = new boolean[18][32];

			for (int i = 0; i < 32; i++) {
				desLeftHalf[0][i] = doRoundsOnThis[i];
				desRightHalf[0][i] = doRoundsOnThis[32+i];
			}
		
			for (int i = 1; i < 17; i++) {
				desLeftHalf[i] = desRightHalf[i-1];
				for (int j = 0; j < 32; j++) {
					desRightHalf[i][j] = (F(desRightHalf[i-1], desSubKeys[16-i])[j] != desLeftHalf[i-1][j]);
				}
			}
		
			desLeftHalf[17] = desRightHalf[16].clone();
			desRightHalf[17] = desLeftHalf[16].clone();
			for (int i = 0; i < 32; i++) {
				theRoundsAreDone[i] = desLeftHalf[17][i];
				theRoundsAreDone[i+32] = desRightHalf[17][i];
			}
			return theRoundsAreDone;
		}
	}

	/**
	 * The Feistel F function for the DES
	 * 
	 * @param input			the right half of the intermediate text,
	 * 						named R_i in the FIPS publication FIPS 46-3
	 * @param desSubKeyI	the subkey for use in the Feistel F function,
	 * 						named K_i in the FIPS publication FIPS 46-3
	 * @return				the 32 bit big-endian array to XOR with L_i
	 * @throws Exception	if the input intermediate text half is not 32 bits
	 * 						or the subkey is not 48 bits
	 */
	private boolean[] F(boolean[] input, boolean[] desSubKeyI) throws Exception {
		if (input.length != 32) {
			throw new Exception("input to F() must be 32 bits");
		} else if (desSubKeyI.length != 48) {
			throw new Exception("desSubKeyI in F() must be 48 bits");
		} else {
			boolean[] tmp = new boolean[48];
			for (int i = 0; i < 48; i++) {
				tmp[i] = (Expand(input)[i] != desSubKeyI[i]);
			}
			boolean[] postS = new boolean[32];
			postS = SBoxMath(tmp);
			return PermutationP(postS);
		}
	}

	/**
	 * Does the 8 S-Box table lookups described in the DES
	 * 
	 * @param theSBoxInput	the 8, 6 bit arrays for input to the DES S-Boxes as
	 * 						a 48 bit big-endian array
	 * @return				the 32 bit output from the DES S-Boxes
	 * @throws Exception	if the input is not 48 bits
	 */
	private boolean[] SBoxMath(boolean[] theSBoxInput) throws Exception {
		if (theSBoxInput.length != 48) {
			throw new Exception("SBoxInput must be 48 bits");
		} else {
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
	}

	/**
	 * Permutes a 32 bit big-endian array using the DES permutation P.
	 * This step is done after the S-Box table lookup
	 * 
	 * @param toPermute		the 32 bit big-endian array to permute
	 * @return				the permuted array
	 */
	private boolean[] PermutationP(boolean[] toPermute) {
		boolean[] permuted = new boolean[32];
		for (int i = 0; i < 32; i++) {
			permuted[i] = toPermute[desP[i]-1];
		}
		return permuted;
	}

	/**
	 * Expands a 32 bit big-endian array using the DES expansion permutation
	 * 
	 * @param toExpand		the 32 bit big-endian array to expand
	 * @return				the 48 bit big-endian expanded array
	 */
	private boolean[] Expand(boolean[] toExpand) {
		boolean[] tmp = new boolean[48];
		for (int i = 0; i < 48; i++) {
			tmp[i] = toExpand[desE[i]-1];
		}
		return tmp;
	}

	/**
	 * Builds an array containing all 16 DES subkeys
	 */
	private void makeSubKeys() {
		desSubKeys = new boolean[16][48];
		desKey56 = new boolean[17][56];
		desC = new boolean[17][28];
		desD = new boolean[17][28];
		
		for (int i = 0; i < 56; i++) {
			desKey56[0][i] = desKeyBits[desPC1[i]-1]; 
		}
		
		for (int i = 0; i < 28; i++) {
			desC[0][i] = desKey56[0][i];
			desD[0][i] = desKey56[0][28+i];
		}
		
		for (int i = 1; i < 17; i++) {
			for (int j = 0; j < 28; j++) {
				desKey56[i][j] = desC[i][j] = desC[i-1][(j+desKeySchedule[i-1])%28];
				desKey56[i][28+j] = desD[i][j] = desD[i-1][(j+desKeySchedule[i-1])%28];
			}
		}
		
		for (int i = 0; i < 16; i++) {
			for (int j = 0; j < 48; j++) {
				desSubKeys[i][j] = desKey56[i+1][desPC2[j]-1];
			}
		}
	}
	
	/**
	 * Creates a string containing the hex representation of the plaintext
	 * 
	 * @return	a string containing the hex representation of the plaintext
	 */
	public String getPlainTextString() {
		String PTString = "";
		for (int i = 0; i < 8; i++) {
			PTString += Integer.toString((desPlainTextBytes[i] & 0xff) + 0x100, 16).substring(1);
		}
		return PTString;
	}

	/**
	 * Creates a string containing the hex representation of the key
	 * 
	 * @return	a string containing the hex representation of the key
	 */
	public String getKeyString() {
		String KString = "";
		for (int i = 0; i < 8; i++) {
			KString += Integer.toString((desKeyBytes[i] & 0xff) + 0x100, 16).substring(1);
		}
		return KString;
	}
	
	/**
	 * Creates a string containing the hex representation of the ciphertext
	 * 
	 * @return	a string containing the hex representation of the ciphertext
	 */
	public String getCipherTextString() {
		String CTString = "";
		for (int i = 0; i < 8; i++) {
			CTString += Integer.toString((desCipherTextBytes[i] & 0xff) + 0x100, 16).substring(1);
		}
		return CTString;
	}

	/**
	 * 
	 * @return				8 byte plaintext array
	 */
	public byte[] getPlainTextBytes() {
		return desPlainTextBytes;
	}

	/**
	 * 
	 * @param plaintext		8 byte plaintext array
	 */
	public void setPlainTextBytes(byte[] plainText) {
		desPlainTextBytes = plainText;
	}

	/**
	 * 
	 * @return				8 byte ciphertext array
	 */
	public byte[] getCipherTextBytes() {
		return desCipherTextBytes;
	}

	/**
	 * 
	 * @param cipherText	8 byte ciphertext array
	 */
	public void setCipherTextBytes(byte[] cipherText) {
		desCipherTextBytes = cipherText;
	}

	/**
	 * 
	 * @return				8 byte key array
	 */
	public byte[] getKeyBytes() {
		return desKeyBytes;
	}

	/**
	 * 
	 * @param key			8 byte key array
	 */
	public void setKeyBytes(byte[] key) {
		desKeyBytes = key;
	}

}
