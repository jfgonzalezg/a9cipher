package com.a9development.a9cipher;

public class A9Cipher {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// PT  = 0x02468aceeca86420
		// Key = 0x0f1571c947d9e859
		// CT  = 0xda02ce3a89ecac3b
		
		//byte[] PT = {(byte)0x02, (byte)0x46, (byte)0x8a, (byte)0xce, (byte)0xec, (byte)0xa8, (byte)0x64, (byte)0x20};
		//byte[] K = {(byte)0x0f, (byte)0x15, (byte)0x71, (byte)0xc9, (byte)0x47, (byte)0xd9, (byte)0xe8, (byte)0x59};
		//byte[] CT = {(byte)0xda, (byte)0x02, (byte)0xce, (byte)0x3a, (byte)0x89, (byte)0xec, (byte)0xac, (byte)0x3b};
		
		boolean[] PT = {false, false, false, false, false, false, true, false, false, true, false, false, false, true, true, false, true, false, false, false, true, false, true, false, true, true, false, false, true, true, true, false, true, true, true, false, true, true, false, false, true, false, true, false, true, false, false, false, false, true, true, false, false, true, false, false, false, false, true, false, false, false, false, false};
		boolean[] K = {false, false, false, false, true, true, true, true, false, false, false, true, false, true, false, true, false, true, true, true, false, false, false, true, true, true, false, false, true, false, false, true, false, true, false, false, false, true, true, true, true, true, false, true, true, false, false, true, true, true, true, false, true, false, false, false, false, true, false, true, true, false, false, true};
		boolean[] CT = {true, true, false, true, true, false, true, false, false, false, false, false, false, false, true, false, true, true, false, false, true, true, true, false, false, false, true, true, true, false, true, false, true, false, false, false, true, false, false, true, true, true, true, false, true, true, false, false, true, false, true, false, true, true, false, false, false, false, true, true, true, false, true, true};
		
		try {
			DES theDES = new DES(PT, K);
			theDES.Encrypt();
			
			int PTErr = 0;
			int KErr = 0;
			int CTErr = 0;
			
			System.out.print("Plaintext(b):  ");
			for (int i = 0; i < 64; i++) {
				System.out.print((PT[i])?1:0);
			}
			System.out.println();
			
			System.out.print("Plaintext(j):  ");
			for (int i = 0; i < 64; i++) {
				System.out.print((theDES.getBoolPlainText()[i])?1:0);
			}
			System.out.println();
			
			System.out.print("Error:         ");
			for (int i = 0; i < 64; i++) {
				if (PT[i] != theDES.getBoolPlainText()[i]) {
					System.out.print(1);
					PTErr++;
				} else {
					System.out.print(0);
				}
			}
			System.out.println("\n" + "Total Errors:  " + PTErr + "\n");
			
			System.out.print("Key(b):        ");
			for (int i = 0; i < 64; i++) {
				System.out.print((K[i])?1:0);
			}
			System.out.println();
			
			System.out.print("Key(j):        ");
			for (int i = 0; i < 64; i++) {
				System.out.print((theDES.getBoolKey()[i])?1:0);
			}
			System.out.println();
			
			System.out.print("Error:         ");
			for (int i = 0; i < 64; i++) {
				if (PT[i] != theDES.getBoolPlainText()[i]) {
					System.out.print(1);
					KErr++;
				} else {
					System.out.print(0);
				}
			}
			System.out.println("\n" + "Total Errors:  " + KErr + "\n");
			
			System.out.print("Ciphertext(b): ");
			for (int i = 0; i < 64; i++) {
				System.out.print((CT[i])?1:0);
			}
			System.out.println();
			
			System.out.print("Ciphertext(j): ");
			for (int i = 0; i < 64; i++) {
				System.out.print((theDES.getBoolCipherText()[i])?1:0);
			}
			System.out.println();
			
			System.out.print("Error:         ");
			for (int i = 0; i < 64; i++) {
				if (CT[i] != theDES.getBoolCipherText()[i]) {
					System.out.print(1);
					CTErr++;
				} else {
					System.out.print(0);
				}
			}
			System.out.println("\n" + "Total Errors:  " + CTErr + "\n");
		} catch (Exception e) {
			System.out.println("Something went wrong: " + e);
		}
	}

}
