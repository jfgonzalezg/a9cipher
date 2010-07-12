package com.a9development.ciphertestharness;

import org.junit.Test;

import com.a9development.a9cipher.DESCipher;

import static org.junit.Assert.assertEquals;

public class DESCipherTest {
	
	private final byte[] PT1 = {(byte) 0x02, (byte) 0x46, (byte) 0x8a, (byte) 0xce, (byte) 0xec, (byte) 0xa8, (byte) 0x64, (byte) 0x20};
	private final byte[] K1 = {(byte) 0x0f, (byte) 0x15, (byte) 0x71, (byte) 0xc9, (byte) 0x47, (byte) 0xd9, (byte) 0xe8, (byte) 0x59};
	private final byte[] CT1 = {(byte) 0xda, (byte) 0x02, (byte) 0xce, (byte) 0x3a, (byte) 0x89, (byte) 0xec, (byte) 0xac, (byte) 0x3b};
	private final String PT1STRING = "02468aceeca86420";
	private final String CT1STRING = "da02ce3a89ecac3b";
	
	@Test
	public void testDESEncrypt() throws Exception {
		DESCipher desTester1 = new DESCipher(K1);
		byte[] result = desTester1.encrypt(PT1);
		String resultString = A9Utility.bytesToString(result);
		assertEquals("Result", CT1STRING, resultString);
	}
	
	@Test
	public void testDESDecrypt() throws Exception {
		DESCipher desTester1 = new DESCipher(K1);
		byte[] result = desTester1.decrypt(CT1);
		String resultString = A9Utility.bytesToString(result);
		assertEquals("Result", PT1STRING, resultString);
	}
	
}
