package com.a9development.a9cipher;

public interface A9DigestSpi {

	public byte[] digest(byte[] message);
	public String getAlgorithm();
	public int getDigestSize();
}
