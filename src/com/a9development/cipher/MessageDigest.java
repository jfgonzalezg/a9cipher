package com.a9development.cipher;

public abstract class MessageDigest {

	protected String ALGORITHM;
	protected int DIGEST_SIZE;
	protected int BLOCK_SIZE;
	protected int ROUNDS;
	protected static int[] K;
	
	public byte[] digest(byte[] message) {
		reset();
		byte[] data = padMessage(message);
		setup();
		for (int i = 0; i < data.length / BLOCK_SIZE; i++) {
			byte[] block = new byte[BLOCK_SIZE];
			System.arraycopy(data, i * BLOCK_SIZE, block, 0, BLOCK_SIZE);
			update(i);
		}
		return data;
	}

	protected abstract void setup();
	
	protected abstract byte[] padMessage(byte[] data);
	
	protected abstract void update(int round);
	
	protected abstract void reset();
	
	public String getAlgorithm() {
		return ALGORITHM;
	}

	public int getDigestSize() {
		return DIGEST_SIZE;
	}

}
