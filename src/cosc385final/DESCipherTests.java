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

@Deprecated
public class DESCipherTests {

	private final byte[] PT1 = {(byte) 0x02, (byte) 0x46, (byte) 0x8a, (byte) 0xce, (byte) 0xec, (byte) 0xa8, (byte) 0x64, (byte) 0x20};
	private final byte[] K1 = {(byte) 0x0f, (byte) 0x15, (byte) 0x71, (byte) 0xc9, (byte) 0x47, (byte) 0xd9, (byte) 0xe8, (byte) 0x59};
	private final byte[] CT1 = {(byte) 0xda, (byte) 0x02, (byte) 0xce, (byte) 0x3a, (byte) 0x89, (byte) 0xec, (byte) 0xac, (byte) 0x3b};
	private final String PT1STRING = "02468ace eca86420";
	private final String CT1STRING = "da02ce3a 89ecac3b";
	
	@Test
	public void testEncrypt() throws Exception {
		DESCipher desTester1 = new DESCipher(K1);
		byte[] result = desTester1.encrypt(PT1);
		String resultString = A9Utility.bytesToHex(result);
		assertEquals("Result", CT1STRING, resultString);
	}

	@Test
	public void testDecrypt() throws Exception {
		DESCipher desTester1 = new DESCipher(K1);
		byte[] result = desTester1.decrypt(CT1);
		String resultString = A9Utility.bytesToHex(result);
		assertEquals("Result", PT1STRING, resultString);
	}

}
