package com.a9development.cipher;

public class SHA1 extends MessageDigest {

	int H0, H1, H2, H3, H4;
	int A, B, C, D, E, T;
	
	protected static final int[] K = {0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6};

	public SHA1() {
		ALGORITHM = "SHA-1";
		DIGEST_SIZE = 20;
		BLOCK_SIZE = 64;
		ROUNDS = 80;
	}
	
	@Override
	protected byte[] padMessage(byte[] data) {
		int origLength = data.length;
		int tailLength = origLength % 64;
		int padLength = 0;
		if ((64 - tailLength >= 9))
			padLength = 64 - tailLength;
		else
			padLength = 128 - tailLength;
		byte[] thePad = new byte[padLength];
		thePad[0] = (byte) 0x80;
		long lengthInBits = origLength * 8;
		for (int i = 0; i < 8; i++) {
			thePad[thePad.length - 1 - i] =	(byte) ((lengthInBits >> (8 * i)) & 0xFF);
		}

		byte[] output = new byte[origLength + padLength];

		System.arraycopy(data, 0, output, 0, origLength);
		System.arraycopy(thePad, 0, output, origLength, thePad.length);
		return output;
	}

	@Override
	protected void update(int round) {
		if (round < 20) {
			T = Integer.rotateLeft(A, 5) + f1(A, B, C) + E + K[0] + words[round];
		} else if (20 <= round && round < 40) {
			T = Integer.rotateLeft(A, 5) + f2(A, B, C) + E + K[1] + words[round];
		} else if (40 <= round && round < 60) {
			T = Integer.rotateLeft(A, 5) + f3(A, B, C) + E + K[2] + words[round];
		} else {
			T = Integer.rotateLeft(A, 5) + f4(A, B, C) + E + K[3] + words[round];
		}
		E = D;
		D = C;
		C = Integer.rotateLeft(B, 30);
		B = A;
		A = T;
	}

	@Override
	protected void reset() {
		H0 = 0x67452301;
		H1 = 0xEFCDAB89;
		H2 = 0x98BADCFE;
		H3 = 0x10325476;
		H4 = 0xC3D2E1F0;
	}

	private static int f1(int a, int b, int c) {
		return (c ^ (a & (b ^ c))) + 0x5A827999;
	}

	private static int f2(int a, int b, int c) {
		return (a^b^c) + 0x6ED9EBA1;
	}

	private static int f3(int a, int b, int c) {
		return ((a&b)|(c&(a|b))) + 0x8F1BBCDC;
	}

	private static int f4(int a, int b, int c) {
		return (a^b^c) + 0xCA62C1D6;
	}

	@Override
	protected void setup() {
		// TODO Auto-generated method stub
		
	}
	
}
