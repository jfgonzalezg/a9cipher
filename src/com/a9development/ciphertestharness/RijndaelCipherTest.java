package com.a9development.ciphertestharness;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import com.a9development.a9cipher.RijndaelCipher;


public class RijndaelCipherTest {

	private final int[] PT1 = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
	private final int[] K1 = {0x0f, 0x15, 0x71, 0xc9, 0x47, 0xd9, 0xe8, 0x59, 0x0c, 0xb7, 0xad, 0xd6, 0xaf, 0x7f, 0x67, 0x98};
	private final int[] CT1 = {0xff, 0x0b, 0x84, 0x4a, 0x08, 0x53, 0xbf, 0x7c, 0x69, 0x34, 0xab, 0x43, 0x64, 0x14, 0x8f, 0xb9};
	private final String PT1STRING = "0123456789abcdeffedcba9876543210";
	private final String CT1STRING = "ff0b844a0853bf7c6934ab4364148fb9";
	
	@Test
	public void testRijndaelEncrypt() throws Exception {
		RijndaelCipher rijndaelTester1 = new RijndaelCipher(K1);
		int[] result = rijndaelTester1.encrypt(PT1);
		String resultString = "";
		for (int i = 0; i < 16; i++) {
			resultString += Integer.toString((result[i] & 0xff) + 0x100, 16).substring(1);
		}
		assertEquals("Result", CT1STRING, resultString);
	}
	
	@Test
	public void testRijndaelDecrypt() throws Exception {
		RijndaelCipher rijndaelTester1 = new RijndaelCipher(K1);
		int[] result = rijndaelTester1.decrypt(CT1);
		String resultString = "";
		for (int i = 0; i < 16; i++) {
			resultString += Integer.toString((result[i] & 0xff) + 0x100, 16).substring(1);
		}
		assertEquals("Result", PT1STRING, resultString);
	}
	
}
