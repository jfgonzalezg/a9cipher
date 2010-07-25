package com.a9development.a9cipher.testharness;

import static org.junit.Assert.*;

import org.junit.Test;

import com.a9development.a9cipher.A9Utility;
import com.a9development.a9cipher.RC4Cipher;

public class RC4CipherTests {

	@Test
	public void testEncrypt() throws Exception {
		String key = "Key";
		RC4Cipher rc4 = new RC4Cipher(key.getBytes());
		String actual = A9Utility.bytesToHex(rc4.encrypt("Plaintext".getBytes()));
		String expected = "bbf316e8 d940af0a d3";
		assertEquals("Result", actual, expected);
	}

	@Test
	public void testDecrypt() throws Exception {
		String key = "Key";
		RC4Cipher rc4 = new RC4Cipher(key.getBytes());
		String actual = A9Utility.bytesToHex(rc4.decrypt(A9Utility.hexToBytes("BBF316E8D940AF0AD3")));
		String expected = A9Utility.bytesToHex("Plaintext".getBytes());
		assertEquals("Result", actual, expected);
	}

}
