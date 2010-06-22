package com.a9development.a9cipher;

public class A9Cipher {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		byte[] PT = {(byte)0x02, (byte)0x46, (byte)0x8a, (byte)0xce, (byte)0xec, (byte)0xa8, (byte)0x64, (byte)0x20};
		byte[] K = {(byte)0x0f, (byte)0x15, (byte)0x71, (byte)0xc9, (byte)0x47, (byte)0xd9, (byte)0xe8, (byte)0x59};
		byte[] CT = {(byte)0xda, (byte)0x02, (byte)0xce, (byte)0x3a, (byte)0x89, (byte)0xec, (byte)0xac, (byte)0x3b};
		try {
			DES theDES = new DES(PT, K);
			theDES.Encrypt();
			// This should print "da02ce3a89ecac3b" but doesn't seem to get very close
			System.out.println(theDES.getCipherText());
			System.out.println(CT);
		} catch (Exception e) {
			System.out.println("Something went wrong: " + e);
		}
	}

//	public static byte[] hexStringToByteArray(String s) {
//	    int len = s.length();
//	    byte[] data = new byte[len / 2];
//	    for (int i = 0; i < len; i += 2) {
//	        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
//	                             + Character.digit(s.charAt(i+1), 16));
//	    }
//	    return data;
//	}
}
