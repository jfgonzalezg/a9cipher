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

package cosc385final;

import static org.junit.Assert.*;

import org.junit.Test;

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
