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

import org.junit.runner.RunWith;
import org.junit.runners.Suite;

//import com.a9development.a9cipher.testharness.A9UtilityTests;
//import com.a9development.a9cipher.testharness.DESCipherTests;
//import com.a9development.a9cipher.testharness.RijndaelCipherTests;
//import com.a9development.a9cipher.testharness.SHA1Tests;

import junit.framework.Test;
import junit.framework.TestSuite;

@SuppressWarnings("deprecation")
@RunWith(Suite.class)
@Suite.SuiteClasses({ A9UtilityTests.class, DESCipherTests.class,
		RijndaelCipherTests.class, RC4CipherTests.class, SHA1Tests.class,
		SHA2Tests.class })
@Deprecated
public class AllTests {

	public static Test suite() {
		TestSuite suite = new TestSuite(AllTests.class.getName());
		//$JUnit-BEGIN$
		suite.addTest(AllTests.suite());
		//$JUnit-END$
		return suite;
	}

}
