package com.a9development.cipher;

public class SerpentCipher {

	private int[] serpentKey;
	private static final String ALGORITHM = "Serpent";
	//TODO fill in permutations and sboxes
	private final int[] IP = {};
	private final int[] INVERSEIP = {};
	private final int[][] SBOX = {
			{3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12},
			{15, 12, 2, 7, 9, 0, 5, 10, 1, 11, 14, 8, 6, 13, 3, 4},
			{8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2},
			{0, 15, 11, 8, 12, 9, 6, 3, 13, 1, 2, 4, 10, 7, 5, 14},
			{1, 15, 8, 3, 12, 0, 11, 6, 2, 5, 4, 10, 9, 14, 7, 13},
			{15, 5, 2, 11, 4, 10, 9, 12, 0, 3, 14, 8, 13, 6, 7, 1},
			{7, 2, 12, 5, 8, 4, 6, 11, 14, 9, 1, 15, 13, 3, 10, 0},
			{1, 13, 15, 0, 14, 8, 2, 11, 7, 4, 12, 10, 9, 3, 5, 6}
	};
	private final int[][] INVERSESBOX = {
			{13, 3, 11, 0, 10, 6, 5, 12, 1, 14, 4, 7, 15, 9, 8, 2},
			{5, 8, 2, 14, 15, 6, 12, 3, 11, 4, 7, 9, 1, 13, 10, 0},
			{12, 9, 15, 4, 11, 14, 1, 2, 0, 3, 6, 13, 5, 8, 10, 7},
			{0, 9, 10, 7, 11, 14, 6, 13, 3, 5, 12, 2, 4, 8, 15, 1},
			{5, 0, 8, 3, 10, 9, 7, 14, 2, 12, 11, 6, 4, 15, 13, 1},
			{8, 15, 2, 9, 4, 1, 13, 14, 11, 6, 5, 3, 7, 12, 10, 0},
			{15, 10, 1, 13, 5, 3, 6, 0, 4, 9, 14, 7, 2, 12, 8, 11},
			{3, 0, 6, 13, 9, 14, 15, 8, 5, 12, 11, 7, 10, 1, 4, 2}
	};
	private final int PHI = 0x9e3779b9;
	
	public SerpentCipher(int[] key) throws Exception {
		if (key.length > 8) {
			throw new Exception("key can only be 256b long");
		} else {
			int[] initialKey = {0, 0, 0, 0, 0, 0, 0, 0};
			for (int i = 0; i < key.length; i++)
				initialKey[i] = key[i];
			
		}
	}
	
	public byte[] encrypt(byte[] plaintext) {
		byte[] ciphertext = new byte[32];
		int[][] K = serpentMakeKeys();
		int[][] B = new int[33][4];
		// TODO Implement Serpent algorithm;
		
		return ciphertext;
	}
	
	public byte[] decrypt(byte[] ciphertext) {
		byte[] plaintext = new byte[32];
		int[][] K = serpentMakeKeys();
		int[][] B = new int[33][4];
		// TODO finish decrypting stage
		
		return plaintext;
	}

	private int[][] serpentMakeKeys() {
		int[] prekey = {serpentKey[0], serpentKey[1], serpentKey[2], serpentKey[3], serpentKey[4], serpentKey[5], serpentKey[6], serpentKey[7]};
		int[] W = new int[132];
		int[][] keyMatrix = new int[33][4];
		W[0] = leftRotBits(prekey[0] ^ prekey[3] ^ prekey[5] ^ prekey[7] ^ PHI ^ 0, 11);
		W[1] = leftRotBits(prekey[1] ^ prekey[4] ^ prekey[6] ^ W[0] ^ PHI ^ 1, 11);
		W[2] = leftRotBits(prekey[2] ^ prekey[5] ^ prekey[7] ^ W[1] ^ PHI ^ 2, 11);
		W[3] = leftRotBits(prekey[3] ^ prekey[6] ^ W[0] ^ W[2] ^ PHI ^ 3, 11);
		W[4] = leftRotBits(prekey[4] ^ prekey[7] ^ W[1] ^ W[3] ^ PHI ^ 4, 11);
		W[5] = leftRotBits(prekey[5] ^ W[0] ^ W[2] ^ W[4] ^ PHI ^ 5, 11);
		W[6] = leftRotBits(prekey[6] ^ W[1] ^ W[3] ^ W[5] ^ PHI ^ 6, 11);
		W[7] = leftRotBits(prekey[7] ^ W[2] ^ W[4] ^ W[6] ^ PHI ^ 7, 11);
		for (int i = 8; i < 132; i++) {
			W[i] = leftRotBits(W[i-8] ^ W[i-5] ^ W[i-3] ^ W[i-1] ^ PHI ^ i, 11);
		}
		for (int i = 0; i < 33; i++) {
			int[] temp = {W[4*i], W[4*i + 1], W[4*i + 2], W[4*i + 3]};
			keyMatrix[i] = S(temp, Math.abs((3-i) % 8));
		}
		
		return keyMatrix;
	}

	private int leftRotBits(int i, int j) {
		// TODO Auto-generated method stub
		return 0;
	}

	private int[] IP(int[] plaintext) {
		// TODO Auto-generated method stub
		return null;
	}

	private int[] S(int[] temp, int i) {
		// TODO Auto-generated method stub
		return null;
	}

	private int[] L(int[] s) {
		// TODO Auto-generated method stub
		return null;
	}

	private int[] FP(int[] is) {
		// TODO Auto-generated method stub
		return null;
	}
	
	public String getAlgorithm() {
		return ALGORITHM;
	}
}
