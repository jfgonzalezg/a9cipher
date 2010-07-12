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

	private static int rotLeft(int iVal, int iRot) {
		return (iVal << iRot) | iVal >>> (32 - iRot);
	}
}
