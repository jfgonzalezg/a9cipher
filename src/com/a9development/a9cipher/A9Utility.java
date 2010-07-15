package com.a9development.a9cipher;

public class A9Utility {

	public static String bytesToHex(byte[] b) {
		String s = "";
		for (int i = 0; i < b.length; i++) {
			if (i > 0 && i % 4 == 0) {
				s += " ";
			}
			s += Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);
		}
		return s;
	}
	
	public static byte[] hexToBytes(String s) {
		byte[] b = new byte[s.length() / 2];
		for (int i = 0; i < s.length(); i+=2) {
			b[i/2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i+1), 16));
		}
		return b;
	}
	
	public static byte[] intToByes(int i) {
		byte[] b = new byte[4];
		for (int c = 0; c < 4; c++) {
			b[c] = (byte) ((i >>> (56 - 8 * c)) & 0xff);
		}
		return b;
	}
	
	public static int bytesToInt(byte[] b) throws Exception {
		if (b.length != 4) {
			throw new Exception("b must be 4 bytes");
		} else {
			return (b[0] << 24) + (b[1] << 16) + (b[2] << 8) + b[3];
		}
	}

	public static byte[] longToBytes(long l) {
		byte[] b = new byte[8];
		for (int c = 0; c < 8; c++) {
			b[c] = (byte) ((l >>> (56 - 8 * c)) & 0xffL);
		}
		return b;
	}

}
