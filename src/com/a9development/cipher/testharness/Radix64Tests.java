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

package com.a9development.cipher.testharness;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import com.a9development.cipher.Radix64;

public class Radix64Tests {

	private final byte[] PT1 = {(byte) 0x01, (byte) 0x45, (byte) 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef, (byte) 0xfe, (byte) 0xdc, (byte) 0xba, (byte) 0x98, (byte) 0x54, (byte) 0x32, (byte) 0x10};
	
	@Test
	public void testRadix64() throws Exception {
		assertEquals("Result", "AUVniavN7/7cuphUMhA=", Radix64.encode(PT1));
	}

}
