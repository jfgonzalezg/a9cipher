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

package cosc385final;

@Deprecated
public class SHA1 {

	static int H0, H1, H2, H3, H4;
	
	public SHA1() {
//		ALGORITHM = "SHA1";
//		DIGEST_SIZE = 160;
//		Integer[] H = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
//		Integer[] K = {0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6};
	}
	
	public byte[] digest(byte[] message) {
		H0 = 0x67452301;
		H1 = 0xEFCDAB89;
		H2 = 0x98BADCFE;
		H3 = 0x10325476;
		H4 = 0xC3D2E1F0;
		
		byte[] block = new byte[64];
		byte[] padded = new byte[(message.length + 64 - (message.length % 64))];
		byte[] hashed = new byte[20];
		int A, B, C, D, E, F, K;
		
		// Append 10000... to the message
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
			
			A = H0;
			B = H1;
			C = H2;
			D = H3;
			E = H4;
			
			for (i = 0; i < 80; i++) {
				if (i < 20) {
					F = (B & C) | (~B & D);
					K = 0x5A827999;
				} else if (19 < i && i < 40) {
					F = B ^ C ^ D;
					K = 0x6ED9EBA1;
				} else if (39 < i && i < 60) {
					F = (B & C) | (B & D) | (C & D);
					K = 0x8F1BBCDC;
				} else {
					F = B ^ C ^ D;
					K = 0xCA62C1D6;
				}
				int temp = Integer.rotateLeft(A, 5) + F + E + K + words[i];
				E = D;
				D = C;
				C = Integer.rotateLeft(B, 30);
				B = A;
				A = temp;
			}
			H0 += A;
			H1 += B;
			H2 += C;
			H3 += D;
			H4 += E;
		}
		
		hashed[0] = (byte) ((H0 >>> 24) & 0xff);
		hashed[1] = (byte) ((H0 >>> 16) & 0xff);
		hashed[2] = (byte) ((H0 >>> 8) & 0xff);
		hashed[3] = (byte) (H0 & 0xff);
		hashed[4] = (byte) ((H1 >>> 24) & 0xff);
		hashed[5] = (byte) ((H1 >>> 16) & 0xff);
		hashed[6] = (byte) ((H1 >>> 8) & 0xff);
		hashed[7] = (byte) (H1 & 0xff);
		hashed[8] = (byte) ((H2 >>> 24) & 0xff);
		hashed[9] = (byte) ((H2 >>> 16) & 0xff);
		hashed[10] = (byte) ((H2 >>> 8) & 0xff);
		hashed[11] = (byte) (H2 & 0xff);
		hashed[12] = (byte) ((H3 >>> 24) & 0xff);
		hashed[13] = (byte) ((H3 >>> 16) & 0xff);
		hashed[14] = (byte) ((H3 >>> 8) & 0xff);
		hashed[15] = (byte) (H3 & 0xff);
		hashed[16] = (byte) ((H4 >>> 24) & 0xff);
		hashed[17] = (byte) ((H4 >>> 16) & 0xff);
		hashed[18] = (byte) ((H4 >>> 8) & 0xff);
		hashed[19] = (byte) (H4 & 0xff);
		
		return hashed;
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
		for (int i = 0; i < 8; i++) {
			thePad[thePad.length - 1 - i] =	(byte) ((lengthInBits >> (8 * i)) & 0xFF);
		}

		byte[] output = new byte[origLength + padLength];

		System.arraycopy(data, 0, output, 0, origLength);
		System.arraycopy(thePad, 0, output, origLength, thePad.length);
		return output;
	}

}
