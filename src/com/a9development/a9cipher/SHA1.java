package com.a9development.a9cipher;

public class SHA1 {

	static int[] H, K;
	
	public static byte[] digest(byte[] message) {
		int[] H = new int[5];
		int[] K = new int[4];
		H[0] = 0x67452301;
		H[1] = 0xEFCDAB89;
		H[2] = 0x98BADCFE;
		H[3] = 0x10325476;
		H[4] = 0xC3D2E1F0;
		K[0] = 0x5A827999;
		K[1] = 0x6ED9EBA1;
		K[2] = 0x8F1BBCDC;
		K[3] = 0xCA62C1D6;
		
		byte[] block = new byte[64];
		byte[] padded = new byte[(message.length + 64 - (message.length % 64))];
		byte[] hashed = new byte[20];
		int A, B, C, D, E;
		
		padded = padMessage(message);
		
		for (int i = 0; i < padded.length / 64; i++) {
			System.arraycopy(padded, 64 * i, block, 0, 64);
			
			int[] words = new int[80];
			for (int j = 0; j < 16; j++) {
				words[j] = 0;
				for (int k = 0; k < 4; k++) {
					words[j] |= ((block[j * 4 + k] & 0x000000FF) << (24 - k * 8));
				}
			}
			
			for (int j = 16; j < 80; j++) {
				words[j] = Integer.rotateLeft((words[j-3] ^ words[j-8] ^ words[j-14] ^ words[j-16]), 1);
			}
			
			A = H[0];
			B = H[1];
			C = H[2];
			D = H[3];
			E = H[4];
			
			for (i = 0; i < 80; i++) {
				int temp = Integer.rotateLeft(A, 5) + F(B, C, D, i) + E + K[i/20] + words[i];
				E = D;
				D = C;
				C = Integer.rotateLeft(B, 30);
				B = A;
				A = temp;
			}
			H[0] += A;
			H[1] += B;
			H[2] += C;
			H[3] += D;
			H[4] += E;
		}
		
		for (int i = 0; i < 5; i++) {
			System.arraycopy(A9Utility.intToByes(H[i]), 0, hashed, 4*i, 4);
		}
		
		return hashed;
	}

	private static int F(int b, int c, int d, int i) {
		if (i < 20) {
			return (b & c) | (~b & d);
		} else if (19 < i && i < 40) {
			return b ^ c ^ d;
		} else if (39 < i && i < 60) {
			return (b & c) | (b & d) | (c & d);
		} else {
			return b ^ c ^ d;
		}
	}
	
	private static byte[] padMessage(byte[] data){
		int origLength = data.length;
		int tailLength = origLength%64;
		int padLength = 0;
		if((64 - tailLength >= 9))
			padLength = 64 - tailLength;
		else
			padLength = 128 - tailLength;

		byte[] thePad = new byte[padLength];
		thePad[0] = (byte)0x80;
		long lengthInBits = origLength * 8;
		for(int cnt = 0;cnt < 8;cnt++){
			thePad[thePad.length - 1 - cnt] =
				(byte)((lengthInBits >> (8 * cnt))
						& 0x00000000000000FF);
		}

		byte[] output =
			new byte[origLength + padLength];

		System.arraycopy(data,0,output,0,origLength);
		System.arraycopy(
				thePad,0,output,origLength,thePad.length);
		return output;

	}

}
