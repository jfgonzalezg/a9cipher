package com.a9development.a9cipher;

public class SHA1 {

	static int h0, h1, h2, h3, h4;
	
	public static byte[] digest(byte[] message) {
		h0 = 0x67452301;
		h1 = 0xEFCDAB89;
		h2 = 0x98BADCFE;
		h3 = 0x10325476;
		h4 = 0xC3D2E1F0;
		byte[] block = new byte[64];
		byte[] toHash = new byte[(message.length + 64 - (message.length % 64))];
		byte[] hashed = new byte[20];
		int a, b, c, d, e, f, k;
		
		// Append 10000... to the message
		for (int i = 0; i < message.length; i++) {
			toHash[i] = message[i];
		}
		toHash[message.length] = (byte) 0x80;
		
		// Append 64-bit message length to the message
		long textLength = message.length * 8;
		for (int i = 8; i > 0; i--) {
			toHash[toHash.length - i] = (byte) ((textLength >>> (8 * (i - 1))) & 0xff);
		}
		
		for (int i = 0; i < toHash.length / 64; i++) {
			for (int j = 0; j < 64; j++) {
				block[j] = toHash[64 * i + j];
			}
			
			int[] words = new int[80];
			for (int j = 0; j < 16; j++) {
				words[j] = (block[4*j] << 24) + (block[4*j+1] << 16) + (block[4*j+2] << 8) + block[4*j+3];
			}
			for (int j = 16; j < 80; j++) {
				words[j] = rotLeft((words[j-3] ^ words[j-8] ^ words[j-14] ^ words[j-16]), 1);
			}
			
			a = h0;
			b = h1;
			c = h2;
			d = h3;
			e = h4;
			
			for (i = 0; i < 80; i++) {
				if (i < 20) {
					f = (b & c) | (~b & d);
					k = 0x5A827999;
				} else if (19 < i && i < 40) {
					f = b ^ c ^ d;
					k = 0x6ED9EBA1;
				} else if (39 < i && i < 60) {
					f = (b & c) | (b & d) | (c & d);
					k = 0x8F1BBCDC;
				} else {
					f = b ^ c ^ d;
					k = 0xCA62C1D6;
				}
				int temp = rotLeft(a, 5) + f + e + k + words[i];
				e = d;
				d = c;
				c = rotLeft(b, 30);
				b = a;
				a = temp;
			}
			h0 += a;
			h1 += b;
			h2 += c;
			h3 += d;
			h4 += e;
		}
		
		hashed[0] = (byte) ((h0 >>> 24) & 0xff);
		hashed[1] = (byte) ((h0 >>> 16) & 0xff);
		hashed[2] = (byte) ((h0 >>> 8) & 0xff);
		hashed[3] = (byte) (h0 & 0xff);
		hashed[4] = (byte) ((h1 >>> 24) & 0xff);
		hashed[5] = (byte) ((h1 >>> 16) & 0xff);
		hashed[6] = (byte) ((h1 >>> 8) & 0xff);
		hashed[7] = (byte) (h1 & 0xff);
		hashed[8] = (byte) ((h2 >>> 24) & 0xff);
		hashed[9] = (byte) ((h2 >>> 16) & 0xff);
		hashed[10] = (byte) ((h2 >>> 8) & 0xff);
		hashed[11] = (byte) (h2 & 0xff);
		hashed[12] = (byte) ((h3 >>> 24) & 0xff);
		hashed[13] = (byte) ((h3 >>> 16) & 0xff);
		hashed[14] = (byte) ((h3 >>> 8) & 0xff);
		hashed[15] = (byte) (h3 & 0xff);
		hashed[16] = (byte) ((h4 >>> 24) & 0xff);
		hashed[17] = (byte) ((h4 >>> 16) & 0xff);
		hashed[18] = (byte) ((h4 >>> 8) & 0xff);
		hashed[19] = (byte) (h4 & 0xff);
		
		
		return hashed;
	}
//	
//	public static byte[] hash(byte[] text) {
//		A = 0x67452301;
//		B = 0xEFCDAB89;
//		C = 0x98BADCFE;
//		D = 0x10325476;
//		E = 0xC3D2E1F0;
//		byte[] block = new byte[64];
//		int a,b,c,d,e;
//		byte[] toHash = new byte[(text.length + 64 - (text.length % 64))];
//		byte[] hashed = new byte[20];
//		
//		for (int i = 0; i < text.length; i++) {
//			toHash[i] = text[i];
//		}
//		toHash[text.length] = (byte) 0x80;
//		
//		long lLen = text.length * 8;
//		for (int i = 0; i < 8; i++) {
//			toHash[toHash.length - 1 - i] = (byte) (lLen >> (8 * i));
//		}
//		
//		for (int i = 0; i < toHash.length;) {
//			block[i % 64] = toHash[i++];
//			if (i % 64 == 0) {
//				a = A;
//				b = B;
//				c = C;
//				d = D;
//				e = E;
//				rounds(block);
//				A += a;
//				B += b;
//				C += c;
//				D += d;
//				E += e;
//			}
//		}
//		
//		hashed[0] = (byte) E;
//		hashed[1] = (byte) (E >> 8);
//		hashed[2] = (byte) (E >> 16);
//		hashed[3] = (byte) (E >> 24);
//		hashed[4] = (byte) D;
//		hashed[5] = (byte) (D >> 8);
//		hashed[6] = (byte) (D >> 16);
//		hashed[7] = (byte) (D >> 24);
//		hashed[8] = (byte) C;
//		hashed[9] = (byte) (C >> 8);
//		hashed[10] = (byte) (C >> 16);
//		hashed[11] = (byte) (C >> 24);
//		hashed[12] = (byte) B;
//		hashed[13] = (byte) (B >> 8);
//		hashed[14] = (byte) (B >> 16);
//		hashed[15] = (byte) (B >> 24);
//		hashed[16] = (byte) A;
//		hashed[17] = (byte) (A >> 8);
//		hashed[18] = (byte) (A >> 16);
//		hashed[19] = (byte) (A >> 24);
//		
//		return hashed;
//	}
//
//	private static void rounds(byte[] block) {
//		int [] words = words(block);
//		for (int i = 0; i < 80; i++) {
//			int temp = E + ft(i) + rotate(A, 5) + words[i] + Kt(i);
//			E = D;
//			D = C;
//			C = rotate(B, 30);
//			B = A;
//			A = temp;
//		}
//	}
//	
//	private static int[] words(byte[] block) {
//		int[] words = new int[80];
//		for (int i = 0; i < 80; i++) {
//			if (i < 16) {
//				words[i] = block[4*i] << 24;
//				words[i] |= block[(4*i)+1] << 16;
//				words[i] |= block[(4*i)+2] << 8;
//				words[i] |= block[(4*i)+3];
//			} else {
//				words[i] = rotate(words[i-16] ^ words[i-14] ^ words[i-8] ^ words[i-3], 1);
//			}
//		}
//		return words;
//	}
//	
//	private static int ft(int iRound) {
//		if (iRound < 20)
//			return (B & C) | (~B & D);
//		else if (iRound < 40)
//			return B^C^D;
//		else if (iRound < 60)
//			return ((B&C)|(B&D)|(C&D));
//		else return B^C^D;
//	}
//	
//	private static int Kt(int iRound) {
//		if(iRound < 20)
//			return 0x5A827999;
//		else if(19 < iRound && iRound < 40)
//			return 0x6ED9EBA1;
//		else if(39 < iRound && iRound < 60)
//			return 0x8F1BBCDC;
//		else return 0xCA62C1D6;
//	}
//	
	private static int rotLeft(int iVal, int iRot) {
		return (iVal << iRot) | iVal >>> (32 - iRot);
	}
}
