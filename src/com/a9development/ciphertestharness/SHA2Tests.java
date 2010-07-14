package com.a9development.ciphertestharness;

import static org.junit.Assert.*;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.junit.Test;

import com.a9development.a9cipher.SHA2;

public class SHA2Tests {

	private final String[] TEXT1 = {
			"",
			"The quick brown fox jumps over the lazy dog",
			"The quick brown fox jumps over the lazy cog"
	};
	
	@Test
	public void testDigest224() {
		fail("Not yet implemented");
	}

	@Test
	public void testDigest256() throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		String expectedString = A9Utility.bytesToHex(md.digest(TEXT1[0].getBytes()));
		String actualString = A9Utility.bytesToHex(SHA2.digest(TEXT1[0].getBytes()));
		assertEquals("Result", expectedString, actualString);
	}

	@Test
	public void testDigest384() {
		fail("Not yet implemented");
	}

	@Test
	public void testDigest512() {
		fail("Not yet implemented");
	}

}
