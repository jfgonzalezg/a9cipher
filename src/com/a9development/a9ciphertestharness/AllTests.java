package com.a9development.a9ciphertestharness;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;

import junit.framework.Test;
import junit.framework.TestSuite;

@RunWith(Suite.class)
@Suite.SuiteClasses( { A9UtilityTests.class, DESCipherTests.class, RijndaelCipherTests.class, SHA1Tests.class, SHA2Tests.class } )
public class AllTests {

	public static Test suite() {
		TestSuite suite = new TestSuite(AllTests.class.getName());
		//$JUnit-BEGIN$

		//$JUnit-END$
		return suite;
	}

}
