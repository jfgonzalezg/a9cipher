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
import com.a9development.a9cipher.SHA1;

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
