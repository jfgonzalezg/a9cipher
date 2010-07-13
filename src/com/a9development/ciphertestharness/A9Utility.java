package com.a9development.ciphertestharness;

public class A9Utility {

	public static String bytesToHex(byte[] B) {
		String resultString = "";
		for (int i = 0; i < B.length; i++) {
			resultString += Integer.toString((B[i] & 0xff) + 0x100, 16).substring(1);
		}
		return resultString;
	}
	
	public static byte[] hexToBytes(String s) {
		byte[] bytes = new byte[s.length() / 2];
		for (int i = 0; i < s.length(); i+=2) {
			bytes[i/2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i+1), 16));
		}
		return bytes;
	}
}
