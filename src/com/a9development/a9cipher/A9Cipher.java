package com.a9development.a9cipher;

public interface A9Cipher {

	byte[] encrypt(byte[] plaintext) throws Exception;
	byte[] decrypt(byte[] plaintext) throws Exception;
	String getAlgorithm();
}
