package cosc385final;

import static org.junit.Assert.*;

import org.junit.Test;

public class Radix64Tests {

	private final byte[] PT1 = {(byte) 0x01, (byte) 0x45, (byte) 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef, (byte) 0xfe, (byte) 0xdc, (byte) 0xba, (byte) 0x98, (byte) 0x54, (byte) 0x32, (byte) 0x10};
	
	@Test
	public void testRadix64() throws Exception {
		assertEquals("Result", "AUVniavN7/7cuphUMhA=", Radix64.encode(PT1));
	}

}
