package com.a9development.cipher.testharness;

import static org.junit.Assert.*;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.junit.Test;

import com.a9development.cipher.A9Utility;
import com.a9development.cipher.SHA1;

public class SHA1Tests {

	private final String MESSAGE_0 = "";
	private final String MESSAGE_1 = "The quick brown fox jumps over the lazy dog";
	private final String MESSAGE_2 = "The quick brown fox jumps over the lazy cog";
	
	@Test
	public void testDigest_0() throws NoSuchAlgorithmException {
		MessageDigest md1 = MessageDigest.getInstance("SHA-1");
		SHA1 md2 = new SHA1();
		String expectedString = A9Utility.bytesToHex(md1.digest(MESSAGE_0.getBytes()));
		String actualString = A9Utility.bytesToHex(md2.digest(MESSAGE_0.getBytes()));
		assertEquals("Result", expectedString, actualString);
	}

	public void testDigestB() throws NoSuchAlgorithmException {
		MessageDigest md1 = MessageDigest.getInstance("SHA-1");
		SHA1 md2 = new SHA1();
		String expectedString = A9Utility.bytesToHex(md1.digest(MESSAGE_1.getBytes()));
		String actualString = A9Utility.bytesToHex(md2.digest(MESSAGE_1.getBytes()));
		assertEquals("Result", expectedString, actualString);
	}
	
	public void testDigestC() throws NoSuchAlgorithmException {
		MessageDigest md1 = MessageDigest.getInstance("SHA-1");
		SHA1 md2 = new SHA1();
		String expectedString = A9Utility.bytesToHex(md1.digest(MESSAGE_2.getBytes()));
		String actualString = A9Utility.bytesToHex(md2.digest(MESSAGE_2.getBytes()));
		assertEquals("Result", expectedString, actualString);
	}
}
