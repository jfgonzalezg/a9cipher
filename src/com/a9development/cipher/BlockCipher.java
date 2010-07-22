package com.a9development.cipher;

public abstract class BlockCipher {

	protected String algorithm;
	protected int blockSize;
	protected int numberOfRounds;
	protected String mode;
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
		this.algorithm = algorithm;
		this.key = key;
		this.iv = iv;
		this.mode = mode;
		this.blockSize = blockSize;
		this.numberOfRounds = numberOfRounds;
		roundKeys = new byte[numberOfRounds][blockSize];
	}
	
	public byte[] encrypt(byte[] plaintext) throws Exception {
		makeRoundKeys();
		if (mode == "ECB") {
			return ecbEncrypt(plaintext);
		} else if (mode == "CBC") {
			return cbcEncrypt(plaintext);
		} else if (mode == "CFB") {
			return cfbEncrypt(plaintext);
		} else if (mode == "OFB") {
			return ofbEncrypt(plaintext);
		} else if (mode == "CTR") {
			return ctrEncrypt(plaintext);
		} else {
			throw new Exception("Invalid mode of operation");
		}
	}
	
	public byte[] decrypt(byte[] ciphertext) throws Exception {
		makeRoundKeys();
		if (mode == "ECB") {
			return ecbDecrypt(ciphertext);
		} else if (mode == "CBC") {
			return cbcDecrypt(ciphertext);
		} else if (mode == "CFB") {
			return cfbDecrypt(ciphertext);
		} else if (mode == "OFB") {
			return ofbDecrypt(ciphertext);
		} else if (mode == "CTR") {
			return ctrDecrypt(ciphertext);
		} else {
			throw new Exception("Invalid mode of operation");
		}
	}
	
	private byte[] ecbEncrypt(byte[] plaintext) {
		int textLength = plaintext.length;
		if (textLength % blockSize != 0) {
			textLength += blockSize - (plaintext.length % blockSize);
		}
		int numBlocks = textLength / blockSize;
		byte[] ciphertext = new byte[textLength];
		for (int i = 0; i < numBlocks; i++) {
			System.arraycopy(encryptBlock(plaintext), 0, ciphertext, i * blockSize, blockSize);
		}
		return ciphertext;
	}
	
	private byte[] ecbDecrypt(byte[] ciphertext) {
		int textLength = ciphertext.length;
		if (textLength % blockSize != 0) {
			textLength += blockSize - (ciphertext.length % blockSize);
		}
		int numBlocks = textLength / blockSize;
		byte[] plaintext = new byte[textLength];
		for (int i = 0; i < numBlocks; i++) {
			System.arraycopy(decryptBlock(ciphertext), 0, plaintext, i * blockSize, blockSize);
		}
		return plaintext;
	}
	
	private byte[] cbcEncrypt(byte[] plaintext) {
		int textLength = plaintext.length;
		if (textLength % blockSize != 0) {
			textLength += blockSize - (plaintext.length % blockSize);
		}
		int numBlocks = textLength / blockSize;
		byte[] ciphertext = new byte[textLength];
		byte[] block = new byte[blockSize];
		System.arraycopy(plaintext, 0, block, 0, blockSize);		
		for (int j = 0; j < blockSize; j++) {
			block[j] ^= iv[j];
		}
		System.arraycopy(encryptBlock(block), 0, ciphertext, 0, blockSize);
		for (int i = 1; i < numBlocks; i++) {
			System.arraycopy(plaintext, i*blockSize, block, 0, blockSize);
			for (int j = 0; j < blockSize; j++) {
				block[j] ^= ciphertext[j + ((i - 1) * blockSize)];			// This is kinda nasty looking, and I doubt it's functionality as well... O_-
			}
			System.arraycopy(encryptBlock(block), 0, ciphertext, i*blockSize, blockSize);
		}
		return ciphertext;
	}
	
	private byte[] cbcDecrypt(byte[] ciphertext) {
		int textLength = ciphertext.length;
		if (textLength % blockSize != 0) {
			textLength += blockSize - (ciphertext.length % blockSize);
		}
		int numBlocks = textLength / blockSize;
		byte[] plaintext = new byte[textLength];
		byte[] block = new byte[blockSize];
		System.arraycopy(ciphertext, 0, block, 0, blockSize);
		block = decryptBlock(block.clone());			// there's no way this works...
		for (int j = 0; j < blockSize; j++) {
			block[j] ^= iv[j];
		}
		System.arraycopy(block, 0, plaintext, 0, blockSize);
		for (int i = 1; i < numBlocks; i++) {
			System.arraycopy(ciphertext, i*blockSize, block, 0, blockSize);
			block = decryptBlock(block.clone());		// there's no way this works...
			for (int j = 0; j < blockSize; j++) {
				block[j] ^= ciphertext[j + ((i - 1) * blockSize)];
			}
			System.arraycopy(block, 0, plaintext, i*blockSize, blockSize);
		}
		return plaintext;
	}
	
	public String getMode() {
		return mode;
	}

	public void setMode(String mode) {
		this.mode = mode;
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
		return algorithm;
	}

	public int getBlockSize() {
		return blockSize;
	}

	public int getNumberOfRounds() {
		return numberOfRounds;
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
