//    Copyright 2010 Daniel James Kotowski
//
//    This file is part of A9Cipher.
//
//    A9Cipher is free software: you can redistribute it and/or modify
//    it under the terms of the GNU Lesser General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    A9Cipher is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU Lesser General Public License for more details.
//
//    You should have received a copy of the GNU Lesser General Public License
//    along with A9Cipher.  If not, see <http://www.gnu.org/licenses/>.

package com.a9development.a9cipher.testharness;

import static org.junit.Assert.*;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.junit.Test;

import com.a9development.a9cipher.A9Utility;
import com.a9development.a9cipher.SHA2;

@Deprecated
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
		assertEquals("Result", "23097d22 3405d822 8642a477 bda255b3 2aadbce4 bda0b3f7 e36c9da7", actualString);
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
