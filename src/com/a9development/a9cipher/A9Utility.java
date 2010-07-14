package com.a9development.a9cipher;

public class A9Utility {

	public static String bytesToHex(byte[] b) {
		String s = "";
		for (int i = 0; i < b.length; i++) {
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
		b[0] = (byte) ((i >>> 24) & 0xff);
		b[1] = (byte) ((i >>> 16) & 0xff);
		b[2] = (byte) ((i >>> 8) & 0xff);
		b[3] = (byte) (i & 0xff);
		
		return b;
	}
}
