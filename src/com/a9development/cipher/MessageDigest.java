package com.a9development.cipher;

public abstract class MessageDigest {

	protected String ALGORITHM;
	protected int DIGEST_SIZE;
	protected int BLOCK_SIZE;
	protected Object H, K;
	protected int ROUNDS;
	
	public byte[] digest(byte[] message) {
		byte[] data = padMessage(message);
		for (int i = 0; i < data.length / BLOCK_SIZE; i++) {
			Object[] block = new Object[BLOCK_SIZE];
			System.arraycopy(data, i * BLOCK_SIZE, block, 0, BLOCK_SIZE);
			processMessage(block);
		}
		return buildHash(data);
	}

	protected abstract byte[] padMessage(byte[] data);
	
	protected abstract void processMessage(Object[] data);
	
	protected abstract byte[] buildHash(byte[] data);
	
	public String getAlgorithm() {
		return ALGORITHM;
	}

	public int getDigestSize() {
		return DIGEST_SIZE;
	}

}
