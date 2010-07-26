package com.a9development.cipher;

public abstract class BlockCipher {

	protected String ALGORITHM;
	protected int BLOCK_SIZE;
	protected int ROUNDS;
	protected String MODE;
	
	protected byte[] key;
	protected byte[] iv;		// need to add some checking for null/invalid iv values
	protected byte[][] roundKeys;
	
//	public BlockCipher(String algorithm, byte[] key, byte[] iv, String mode, int numberOfRounds, int blockSize) {
//		this.algorithm = algorithm;
//		this.blockSize = blockSize;
//		this.numberOfRounds = numberOfRounds;
//		this.mode = mode;
//		this.key = key;
//		this.iv = iv;
//	}
	
	public BlockCipher(String algorithm, byte[] key, byte[] iv, String mode, int blockSize, int numberOfRounds) {
		this.ALGORITHM = algorithm;
		this.key = key;
		this.iv = iv;
		this.MODE = mode;
		this.BLOCK_SIZE = blockSize;
		this.ROUNDS = numberOfRounds;
		roundKeys = new byte[numberOfRounds][blockSize];
	}
	
	public byte[] encrypt(byte[] plaintext) throws Exception {
		makeRoundKeys();
		if (MODE == "ECB") {
			return ecbEncrypt(plaintext);
		} else if (MODE == "CBC") {
			return cbcEncrypt(plaintext);
		} else if (MODE == "CFB") {
			return cfbEncrypt(plaintext);
		} else if (MODE == "OFB") {
			return ofbEncrypt(plaintext);
		} else if (MODE == "CTR") {
			return ctrEncrypt(plaintext);
		} else {
			throw new Exception("Invalid mode of operation");
		}
	}
	
	public byte[] decrypt(byte[] ciphertext) throws Exception {
		makeRoundKeys();
		if (MODE == "ECB") {
			return ecbDecrypt(ciphertext);
		} else if (MODE == "CBC") {
			return cbcDecrypt(ciphertext);
		} else if (MODE == "CFB") {
			return cfbDecrypt(ciphertext);
		} else if (MODE == "OFB") {
			return ofbDecrypt(ciphertext);
		} else if (MODE == "CTR") {
			return ctrDecrypt(ciphertext);
		} else {
			throw new Exception("Invalid mode of operation");
		}
	}
	
	private byte[] ecbEncrypt(byte[] plaintext) {
		int textLength = plaintext.length;
		if (textLength % BLOCK_SIZE != 0) {
			textLength += BLOCK_SIZE - (plaintext.length % BLOCK_SIZE);
		}
		int numBlocks = textLength / BLOCK_SIZE;
		byte[] ciphertext = new byte[textLength];
		for (int i = 0; i < numBlocks; i++) {
			System.arraycopy(encryptBlock(plaintext), 0, ciphertext, i * BLOCK_SIZE, BLOCK_SIZE);
		}
		return ciphertext;
	}
	
	private byte[] ecbDecrypt(byte[] ciphertext) {
		int textLength = ciphertext.length;
		if (textLength % BLOCK_SIZE != 0) {
			textLength += BLOCK_SIZE - (ciphertext.length % BLOCK_SIZE);
		}
		int numBlocks = textLength / BLOCK_SIZE;
		byte[] plaintext = new byte[textLength];
		for (int i = 0; i < numBlocks; i++) {
			System.arraycopy(decryptBlock(ciphertext), 0, plaintext, i * BLOCK_SIZE, BLOCK_SIZE);
		}
		return plaintext;
	}
	
	private byte[] cbcEncrypt(byte[] plaintext) {
		int textLength = plaintext.length;
		if (textLength % BLOCK_SIZE != 0) {
			textLength += BLOCK_SIZE - (plaintext.length % BLOCK_SIZE);
		}
		int numBlocks = textLength / BLOCK_SIZE;
		byte[] ciphertext = new byte[textLength];
		byte[] block = new byte[BLOCK_SIZE];
		System.arraycopy(plaintext, 0, block, 0, BLOCK_SIZE);		
		for (int j = 0; j < BLOCK_SIZE; j++) {
			block[j] ^= iv[j];
		}
		System.arraycopy(encryptBlock(block), 0, ciphertext, 0, BLOCK_SIZE);
		for (int i = 1; i < numBlocks; i++) {
			System.arraycopy(plaintext, i*BLOCK_SIZE, block, 0, BLOCK_SIZE);
			for (int j = 0; j < BLOCK_SIZE; j++) {
				block[j] ^= ciphertext[j + ((i - 1) * BLOCK_SIZE)];			// This is kinda nasty looking, and I doubt it's functionality as well... O_-
			}
			System.arraycopy(encryptBlock(block), 0, ciphertext, i*BLOCK_SIZE, BLOCK_SIZE);
		}
		return ciphertext;
	}
	
	private byte[] cbcDecrypt(byte[] ciphertext) {
		int textLength = ciphertext.length;
		if (textLength % BLOCK_SIZE != 0) {
			textLength += BLOCK_SIZE - (ciphertext.length % BLOCK_SIZE);
		}
		int numBlocks = textLength / BLOCK_SIZE;
		byte[] plaintext = new byte[textLength];
		byte[] block = new byte[BLOCK_SIZE];
		System.arraycopy(ciphertext, 0, block, 0, BLOCK_SIZE);
		block = decryptBlock(block.clone());			// there's no way this works...
		for (int j = 0; j < BLOCK_SIZE; j++) {
			block[j] ^= iv[j];
		}
		System.arraycopy(block, 0, plaintext, 0, BLOCK_SIZE);
		for (int i = 1; i < numBlocks; i++) {
			System.arraycopy(ciphertext, i*BLOCK_SIZE, block, 0, BLOCK_SIZE);
			block = decryptBlock(block.clone());		// there's no way this works...
			for (int j = 0; j < BLOCK_SIZE; j++) {
				block[j] ^= ciphertext[j + ((i - 1) * BLOCK_SIZE)];
			}
			System.arraycopy(block, 0, plaintext, i*BLOCK_SIZE, BLOCK_SIZE);
		}
		return plaintext;
	}
	
	public String getMode() {
		return MODE;
	}

	public void setMode(String mode) {
		this.MODE = mode;
	}

	public byte[] getKey() {
		return key;
	}

	public void setKey(byte[] key) {
		this.key = key;
	}

	public byte[] getIv() {
		return iv;
	}

	public void setIv(byte[] iv) {
		this.iv = iv;
	}

	public String getAlgorithm() {
		return ALGORITHM;
	}

	public int getBlockSize() {
		return BLOCK_SIZE;
	}

	public int getNumberOfRounds() {
		return ROUNDS;
	}

	private byte[] cfbEncrypt(byte[] plaintext) {
		
		return null;
	}

	private byte[] cfbDecrypt(byte[] ciphertext) {
		
		return null;
	}
	
	private byte[] ofbEncrypt(byte[] plaintext) {
		
		return null;
	}

	private byte[] ofbDecrypt(byte[] ciphertext) {
		
		return null;
	}
	
	private byte[] ctrEncrypt(byte[] plaintext) {
		
		return null;
	}

	private byte[] ctrDecrypt(byte[] ciphertext) {
		
		return null;
	}
	
	protected abstract byte[] encryptBlock(byte[] plaintext);
	protected abstract byte[] decryptBlock(byte[] ciphertext);
	protected abstract byte[] encryptionRound(byte[] roundBytes, int roundNumber);
	protected abstract byte[] decryptionRound(byte[] roundBytes, int roundNumber);
	protected abstract void makeRoundKeys();

}
