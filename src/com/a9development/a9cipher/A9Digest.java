package com.a9development.a9cipher;

public interface A9Digest {

	public byte[] digest(byte[] message);
	public String getAlgorithm();
	public int getDigestSize();
}
