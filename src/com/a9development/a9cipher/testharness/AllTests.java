package com.a9development.a9cipher.testharness;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;

//import com.a9development.a9cipher.testharness.A9UtilityTests;
//import com.a9development.a9cipher.testharness.DESCipherTests;
//import com.a9development.a9cipher.testharness.RijndaelCipherTests;
//import com.a9development.a9cipher.testharness.SHA1Tests;

import junit.framework.Test;
import junit.framework.TestSuite;

@RunWith(Suite.class)
@Suite.SuiteClasses({ A9UtilityTests.class, DESCipherTests.class,
		RijndaelCipherTests.class, RC4CipherTests.class, SHA1Tests.class,
		SHA2Tests.class })
public class AllTests {

	public static Test suite() {
		TestSuite suite = new TestSuite(AllTests.class.getName());
		//$JUnit-BEGIN$
		suite.addTest(AllTests.suite());
		//$JUnit-END$
		return suite;
	}

}
