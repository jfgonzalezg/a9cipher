package com.a9development.a9cipher;

public class A9Cipher {
	// TODO Rewrite this whole thing. It's straight terribad.
	
//	private byte[] initializationVector;
//	private String padding;
//	private String algorithm;
//	private String mode;
//		
//	public A9Cipher(String algorithm) throws NullPointerException, Exception {
//		if (algorithm == null) {
//			throw new NullPointerException();
//		} else if (algorithm == "DES") {
//			this.algorithm = algorithm;
//			padding = "NoPadding";
//			mode = "ECB";
//		} else if (algorithm == "AES" || algorithm == "Rijndael") {
//			this.algorithm = algorithm;
//			padding = "NoPadding";
//			mode = "ECB";
//		} else {
//			throw new Exception("must choose from DES, AES, or Rijndael");
//		}
//	}
//	
//	public A9Cipher(String algorithm, String mode, String padding) throws NullPointerException, Exception {
//		if (algorithm == null || mode == null || padding == null) {
//			throw new NullPointerException();
//		} else {
//			if (algorithm != "AES" && algorithm != "DES" && algorithm != "Rijndael") {
//				throw new Exception("algorithm must be one of DES, AES, or Rijndael");
//			} else {
//				this.algorithm = algorithm;
//			}
//			if (mode != "ECB" && mode != "CBC" && mode != "CFB" && mode != "OFB" && mode != "CTR") {
//				throw new Exception("mode must be one of ECB, CBC, CFB, OFB, or CTR");
//			} else {
//				this.mode = mode;
//			}
//			if (padding != "NullPadding") {
//				throw new Exception("padding must be one of NullPadding");
//			} else {
//				this.padding = padding;
//			}
//		}
//	}
//	
//	public byte[] encrypt(byte[] key, byte[] iv, byte[] plaintext) throws Exception {
//
//		
//		byte[] paddedPlaintext;
//		int blocksize = 0;
//		Object encrypter;
//		
//		if (algorithm == "DES") {
//			DESCipher encrypter = new DESCipher(key);
//			blocksize = 8;
//		} else if (algorithm == "AES" || algorithm == "Rijndael") {
//			RijndaelCipher encrypter = new RijndaelCipher(key);
//			blocksize = 16;
//		}
//		
//		if (padding == "NullPadding") {
//			paddedPlaintext = nullPad(plaintext);
//			byte[] ciphertext = new byte[paddedPlaintext.length];
//		}
//		
//		if (mode == "ECB") {
//			for (int i = 0; i < (paddedPlaintext.length / blocksize); i++) {
//				for (int j = 0; j < blocksize; j++) {
//					byte[] ptBlock = new byte[blocksize];
//					for (int k = 0; k < blocksize; k++) {
//						ptBlock = 
//					}
//					ciphertext[blocksize * i + j] = encrypter.encrypt(ptBlock);
//				}
//			}
//			
//		} else if (mode == "CBC") {
//
//		} else if (mode == "CFB") {
//			
//		} else if (mode == "OFB") {
//			
//		} else if (mode == "CTR") {
//			
//		}
//				
//		return ciphertext;
//	}
//	
//	private byte[] nullPad(byte[] pad) {
//		byte[] padded;
//		int padToNearest = 0;
//		if (algorithm == "DES") {
//			padToNearest = 8;
//		} else if (algorithm == "AES" || algorithm == "Rijndael") {
//			padToNearest = 16;
//		}
//		if ((pad.length % padToNearest) != 0) {
//			padded = new byte[pad.length + (padToNearest - (pad.length % padToNearest))];
//		} else {
//			padded = new byte[pad.length];
//		}
//		for (int i = 0; i < pad.length; i++) {
//			padded[i] = pad[i];
//		}
//		return padded;
//	}
}
