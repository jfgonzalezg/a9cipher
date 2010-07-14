package com.a9development.ciphertestharness;

import static org.junit.Assert.*;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.junit.Test;

import com.a9development.a9cipher.SHA2;

public class SHA2Tests {

	private final String MESSAGE_0 = "";
	private final String MESSAGE_1 = "The quick brown fox jumps over the lazy dog";
	private final String MESSAGE_2 = "The quick brown fox jumps over the lazy cog";
	
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
