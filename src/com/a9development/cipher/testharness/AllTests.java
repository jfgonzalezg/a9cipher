package com.a9development.cipher.testharness;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;

//import com.a9development.cipher.testharness.A9UtilityTests;
//import com.a9development.cipher.testharness.DESCipherTests;
//import com.a9development.cipher.testharness.RijndaelCipherTests;
//import com.a9development.cipher.testharness.SHA1Tests;

import junit.framework.Test;
import junit.framework.TestSuite;

@RunWith(Suite.class)
@Suite.SuiteClasses( { A9UtilityTests.class, DESCipherTests.class, RijndaelCipherTests.class, Radix64Tests.class } )
public class AllTests {

	public static Test suite() {
		TestSuite suite = new TestSuite(AllTests.class.getName());
		//$JUnit-BEGIN$

		//$JUnit-END$
		return suite;
	}

}
