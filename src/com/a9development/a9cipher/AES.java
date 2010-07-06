package com.a9development.a9cipher;

// A wrapper around the RijndaelCipher class that lets it be used as AESCipher as well.
public class AES {
	private Rijndael rd;
	
	public AES(int[] key) throws Exception {
		rd = new Rijndael(key);
	}
	
	public int[] encrypt(int[] plaintext) throws Exception {
		return rd.encrypt(plaintext);
	}
	
	public int[] decrypt(int[] ciphertext) throws Exception {
		return rd.decrypt(ciphertext);
	}
	
	public int[] getAesKey() {
		return rd.getRijndaelKey();
	}

	public void setAESKey(int[] aesKey) {
		rd.setRijndaelKey(aesKey);
	}

}
