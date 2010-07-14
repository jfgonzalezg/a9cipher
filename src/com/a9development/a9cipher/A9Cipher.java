package com.a9development.a9cipher;

public interface A9Cipher {

	public byte[] encrypt(byte[] plaintext) throws Exception;
	public byte[] decrypt(byte[] plaintext) throws Exception;
	public String getAlgorithm();
}
