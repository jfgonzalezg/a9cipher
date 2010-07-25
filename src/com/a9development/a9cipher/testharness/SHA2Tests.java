package com.a9development.a9cipher.testharness;

import static org.junit.Assert.*;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.junit.Test;

import com.a9development.a9cipher.A9Utility;
import com.a9development.a9cipher.SHA2;

public class SHA2Tests {

	private final String MESSAGE_0 = "abc";
	private final String MESSAGE_1 = "The quick brown fox jumps over the lazy dog";
	private final String MESSAGE_2 = "The quick brown fox jumps over the lazy cog";
	
	@Test
	public void testDigestByteArray_224_0() throws NoSuchAlgorithmException {
//		MessageDigest md1 = MessageDigest.getInstance("SHA-224");
		SHA2 md2 = new SHA2("SHA-224");
//		String expectedString = A9Utility.bytesToHex(md1.digest(MESSAGE_0.getBytes()));
		String actualString = A9Utility.bytesToHex(md2.digest(MESSAGE_0.getBytes()));
//		assertEquals("Result", expectedString, actualString);
		assertEquals("Result", "d14a028c 2a3a2bc9 476102bb 288234c4 15a2b01f 828ea62a c5b3e42f", actualString);
	}

	@Test
	public void testDigestByteArray_224_1() throws NoSuchAlgorithmException {
//		MessageDigest md1 = MessageDigest.getInstance("SHA-224");
		SHA2 md2 = new SHA2("SHA-224");
//		String expectedString = A9Utility.bytesToHex(md1.digest(MESSAGE_1.getBytes()));
		String actualString = A9Utility.bytesToHex(md2.digest(MESSAGE_1.getBytes()));
//		assertEquals("Result", expectedString, actualString);
		assertEquals("Result", "730e109b d7a8a32b 1cb9d9a0 9aa2325d 2430587d dbc0c38b ad911525", actualString);
	}

	@Test
	public void testDigestByteArray_224_2() throws NoSuchAlgorithmException {
//		MessageDigest md1 = MessageDigest.getInstance("SHA-224");
		SHA2 md2 = new SHA2("SHA-224");
//		String expectedString = A9Utility.bytesToHex(md1.digest(MESSAGE_2.getBytes()));
		String actualString = A9Utility.bytesToHex(md2.digest(MESSAGE_2.getBytes()));
//		assertEquals("Result", expectedString, actualString);
		assertEquals("Result", "fee755f4 4a55f20f b3362cdc 3c493615 b3cb574e d95ce610 ee5b1e9b", actualString);
	}

	@Test
	public void testDigestByteArray_256_0() throws NoSuchAlgorithmException {
		MessageDigest md1 = MessageDigest.getInstance("SHA-256");
		SHA2 md2 = new SHA2("SHA-256");
		String expectedString = A9Utility.bytesToHex(md1.digest(MESSAGE_0.getBytes()));
		String actualString = A9Utility.bytesToHex(md2.digest(MESSAGE_0.getBytes()));
		assertEquals("Result", expectedString, actualString);
	}

	@Test
	public void testDigestByteArray_256_1() throws NoSuchAlgorithmException {
		MessageDigest md1 = MessageDigest.getInstance("SHA-256");
		SHA2 md2 = new SHA2("SHA-256");
		String expectedString = A9Utility.bytesToHex(md1.digest(MESSAGE_1.getBytes()));
		String actualString = A9Utility.bytesToHex(md2.digest(MESSAGE_1.getBytes()));
		assertEquals("Result", expectedString, actualString);
	}

	@Test
	public void testDigestByteArray_256_2() throws NoSuchAlgorithmException {
		MessageDigest md1 = MessageDigest.getInstance("SHA-256");
		SHA2 md2 = new SHA2("SHA-256");
		String expectedString = A9Utility.bytesToHex(md1.digest(MESSAGE_2.getBytes()));
		String actualString = A9Utility.bytesToHex(md2.digest(MESSAGE_2.getBytes()));
		assertEquals("Result", expectedString, actualString);
	}

	@Test
	public void testDigestByteArray_384_0() throws NoSuchAlgorithmException {
		MessageDigest md1 = MessageDigest.getInstance("SHA-384");
		SHA2 md2 = new SHA2("SHA-384");
		String expectedString = A9Utility.bytesToHex(md1.digest(MESSAGE_0.getBytes()));
		String actualString = A9Utility.bytesToHex(md2.digest(MESSAGE_0.getBytes()));
		assertEquals("Result", expectedString, actualString);
	}

	@Test
	public void testDigestByteArray_384_1() throws NoSuchAlgorithmException {
		MessageDigest md1 = MessageDigest.getInstance("SHA-384");
		SHA2 md2 = new SHA2("SHA-384");
		String expectedString = A9Utility.bytesToHex(md1.digest(MESSAGE_1.getBytes()));
		String actualString = A9Utility.bytesToHex(md2.digest(MESSAGE_1.getBytes()));
		assertEquals("Result", expectedString, actualString);
	}

	@Test
	public void testDigestByteArray_384_2() throws NoSuchAlgorithmException {
		MessageDigest md1 = MessageDigest.getInstance("SHA-384");
		SHA2 md2 = new SHA2("SHA-384");
		String expectedString = A9Utility.bytesToHex(md1.digest(MESSAGE_2.getBytes()));
		String actualString = A9Utility.bytesToHex(md2.digest(MESSAGE_2.getBytes()));
		assertEquals("Result", expectedString, actualString);
	}

	@Test
	public void testDigestByteArray_512_0() throws NoSuchAlgorithmException {
		MessageDigest md1 = MessageDigest.getInstance("SHA-512");
		SHA2 md2 = new SHA2("SHA-512");
		String expectedString = A9Utility.bytesToHex(md1.digest(MESSAGE_0.getBytes()));
		String actualString = A9Utility.bytesToHex(md2.digest(MESSAGE_0.getBytes()));
		assertEquals("Result", expectedString, actualString);
	}

	@Test
	public void testDigestByteArray_512_1() throws NoSuchAlgorithmException {
		MessageDigest md1 = MessageDigest.getInstance("SHA-512");
		SHA2 md2 = new SHA2("SHA-512");
		String expectedString = A9Utility.bytesToHex(md1.digest(MESSAGE_1.getBytes()));
		String actualString = A9Utility.bytesToHex(md2.digest(MESSAGE_1.getBytes()));
		assertEquals("Result", expectedString, actualString);
	}

	@Test
	public void testDigestByteArray_512_2() throws NoSuchAlgorithmException {
		MessageDigest md1 = MessageDigest.getInstance("SHA-512");
		SHA2 md2 = new SHA2("SHA-512");
		String expectedString = A9Utility.bytesToHex(md1.digest(MESSAGE_2.getBytes()));
		String actualString = A9Utility.bytesToHex(md2.digest(MESSAGE_2.getBytes()));
		assertEquals("Result", expectedString, actualString);
	}

}
