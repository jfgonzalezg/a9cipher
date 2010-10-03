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

import org.junit.Test;

import com.a9development.a9cipher.A9Utility;

@Deprecated
public class A9UtilityTests {

	byte[] B1 = {(byte) 0x02, (byte) 0x46, (byte) 0x8a, (byte) 0xce, (byte) 0xec, (byte) 0xa8, (byte) 0x64, (byte) 0x20};
	byte[] B2 = {(byte) 0x02, (byte) 0x46, (byte) 0x8a, (byte) 0xce};
	byte B3 = (byte) 0xba;
	boolean[] bits1 = {true, false, true, true, true, false, true, false};
	boolean[] bits2 = {false, false, false, false, false, false, true, false, false, true, false, false, false, true, true, false, true, false, false, false, true, false, true, false, true, true, false, false, true, true, true, false, true, true, true, false, true, true, false, false, true, false, true, false, true, false, false, false, false, true, true, false, false, true, false, false, false, false, true, false, false, false, false, false};
	String H1 = "02468aceeca86420";
	String H2 = "02468ace eca86420";
	int I1 = 0x02468ace;
	long L1 = 0x02468aceeca86420L;



	@Test
	public void testBytesToHex() {
		assertEquals("Result", A9Utility.bytesToHex(B1), H2);
	}

	@Test
	public void testHexToBytes() {
		assertTrue("Result", java.util.Arrays.equals(A9Utility.hexToBytes(H1), B1));
	}

	@Test
	public void testIntToByes() {
		assertTrue("Result", java.util.Arrays.equals(A9Utility.intToBytes(I1), B2));
	}

	@Test
	public void testBytesToInt() {
		assertEquals("Result", A9Utility.bytesToInt(B2), I1);
	}

	@Test
	public void testLongToBytes() {
		assertTrue("Result", java.util.Arrays.equals(A9Utility.longToBytes(L1), B1));
	}

	@Test
	public void testByteToBits() {
		assertTrue("Result", java.util.Arrays.equals(A9Utility.byteToBits(B3), bits1));
	}

	@Test
	public void testBitsTo8Bytes() {
		assertTrue("Result", java.util.Arrays.equals(A9Utility.bitsTo8Bytes(bits2), B1));
	}

}
