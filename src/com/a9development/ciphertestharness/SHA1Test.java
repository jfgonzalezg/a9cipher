package com.a9development.ciphertestharness;

import static org.junit.Assert.assertEquals;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.junit.Test;

import com.a9development.a9cipher.SHA1;


public class SHA1Test {

	
	
	private final String[] TEXT1 = {
			"",
			"The quick brown fox jumps over the lazy dog",
			"The quick brown fox jumps over the lazy cog"
	};
	
	@Test
	public void testSHA1a() throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		String expectedString = A9Utility.bytesToString(md.digest(TEXT1[0].getBytes()));
		String actualString = A9Utility.bytesToString(SHA1.digest(TEXT1[0].getBytes()));
		assertEquals("Result", expectedString, actualString);
	}
	
	@Test
	public void testSHA1b() throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		String expectedString = A9Utility.bytesToString(md.digest(TEXT1[1].getBytes()));
		String actualString = A9Utility.bytesToString(SHA1.digest(TEXT1[1].getBytes()));
		assertEquals("Result", expectedString, actualString);
	}
	
	@Test
	public void testSHA1c() throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		String expectedString = A9Utility.bytesToString(md.digest(TEXT1[2].getBytes()));
		String actualString = A9Utility.bytesToString(SHA1.digest(TEXT1[2].getBytes()));
		assertEquals("Result", expectedString, actualString);
	}
}
