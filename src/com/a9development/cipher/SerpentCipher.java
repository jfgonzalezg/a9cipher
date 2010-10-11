//    Copyright 2010 Daniel James Kotowski
//
//    This file is part of A9Cipher.
//
//    A9Cipher is free software: you can redistribute it and/or modify
//    it under the terms of the GNU Lesser General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    A9Cipher is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU Lesser General Public License for more details.
//
//    You should have received a copy of the GNU Lesser General Public License
//    along with A9Cipher.  If not, see <http://www.gnu.org/licenses/>.

package com.a9development.cipher;

import com.a9development.A9Utility;

public class SerpentCipher extends BlockCipher {

	private static final byte[][] Sbox = new byte[][] {
			{ 3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12 },
			{ 15, 12, 2, 7, 9, 0, 5, 10, 1, 11, 14, 8, 6, 13, 3, 4 },
			{ 8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2 },
			{ 0, 15, 11, 8, 12, 9, 6, 3, 13, 1, 2, 4, 10, 7, 5, 14 },
			{ 1, 15, 8, 3, 12, 0, 11, 6, 2, 5, 4, 10, 9, 14, 7, 13 },
			{ 15, 5, 2, 11, 4, 10, 9, 12, 0, 3, 14, 8, 13, 6, 7, 1 },
			{ 7, 2, 12, 5, 8, 4, 6, 11, 14, 9, 1, 15, 13, 3, 10, 0 },
			{ 1, 13, 15, 0, 14, 8, 2, 11, 7, 4, 12, 10, 9, 3, 5, 6 } };

	private static final byte[][] SboxInverse = new byte[][] {
			{ 13, 3, 11, 0, 10, 6, 5, 12, 1, 14, 4, 7, 15, 9, 8, 2 },
			{ 5, 8, 2, 14, 15, 6, 12, 3, 11, 4, 7, 9, 1, 13, 10, 0 },
			{ 12, 9, 15, 4, 11, 14, 1, 2, 0, 3, 6, 13, 5, 8, 10, 7 },
			{ 0, 9, 10, 7, 11, 14, 6, 13, 3, 5, 12, 2, 4, 8, 15, 1 },
			{ 5, 0, 8, 3, 10, 9, 7, 14, 2, 12, 11, 6, 4, 15, 13, 1 },
			{ 8, 15, 2, 9, 4, 1, 13, 14, 11, 6, 5, 3, 7, 12, 10, 0 },
			{ 15, 10, 1, 13, 5, 3, 6, 0, 4, 9, 14, 7, 2, 12, 8, 11 },
			{ 3, 0, 6, 13, 9, 14, 15, 8, 5, 12, 11, 7, 10, 1, 4, 2 } };

	private static final byte[] IPtable = new byte[] { 0, 32, 64, 96, 1, 33,
			65, 97, 2, 34, 66, 98, 3, 35, 67, 99, 4, 36, 68, 100, 5, 37, 69,
			101, 6, 38, 70, 102, 7, 39, 71, 103, 8, 40, 72, 104, 9, 41, 73,
			105, 10, 42, 74, 106, 11, 43, 75, 107, 12, 44, 76, 108, 13, 45, 77,
			109, 14, 46, 78, 110, 15, 47, 79, 111, 16, 48, 80, 112, 17, 49, 81,
			113, 18, 50, 82, 114, 19, 51, 83, 115, 20, 52, 84, 116, 21, 53, 85,
			117, 22, 54, 86, 118, 23, 55, 87, 119, 24, 56, 88, 120, 25, 57, 89,
			121, 26, 58, 90, 122, 27, 59, 91, 123, 28, 60, 92, 124, 29, 61, 93,
			125, 30, 62, 94, 126, 31, 63, 95, 127 };

	private static final byte[] FPtable = new byte[] { 0, 4, 8, 12, 16, 20, 24,
			28, 32, 36, 40, 44, 48, 52, 56, 60, 64, 68, 72, 76, 80, 84, 88, 92,
			96, 100, 104, 108, 112, 116, 120, 124, 1, 5, 9, 13, 17, 21, 25, 29,
			33, 37, 41, 45, 49, 53, 57, 61, 65, 69, 73, 77, 81, 85, 89, 93, 97,
			101, 105, 109, 113, 117, 121, 125, 2, 6, 10, 14, 18, 22, 26, 30,
			34, 38, 42, 46, 50, 54, 58, 62, 66, 70, 74, 78, 82, 86, 90, 94, 98,
			102, 106, 110, 114, 118, 122, 126, 3, 7, 11, 15, 19, 23, 27, 31,
			35, 39, 43, 47, 51, 55, 59, 63, 67, 71, 75, 79, 83, 87, 91, 95, 99,
			103, 107, 111, 115, 119, 123, 127 };

	private static final byte[][] LTtable = new byte[][] {
			{ 16, 52, 56, 70, 83, 94, 105, (byte) 0xFF },
			{ 72, 114, 125, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 2, 9, 15, 30, 76, 84, 126, (byte) 0xFF },
			{ 36, 90, 103, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 20, 56, 60, 74, 87, 98, 109, (byte) 0xFF },
			{ 1, 76, 118, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 2, 6, 13, 19, 34, 80, 88, (byte) 0xFF },
			{ 40, 94, 107, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 24, 60, 64, 78, 91, 102, 113, (byte) 0xFF },
			{ 5, 80, 122, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 6, 10, 17, 23, 38, 84, 92, (byte) 0xFF },
			{ 44, 98, 111, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 28, 64, 68, 82, 95, 106, 117, (byte) 0xFF },
			{ 9, 84, 126, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 10, 14, 21, 27, 42, 88, 96, (byte) 0xFF },
			{ 48, 102, 115, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 32, 68, 72, 86, 99, 110, 121, (byte) 0xFF },
			{ 2, 13, 88, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 14, 18, 25, 31, 46, 92, 100, (byte) 0xFF },
			{ 52, 106, 119, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 36, 72, 76, 90, 103, 114, 125, (byte) 0xFF },
			{ 6, 17, 92, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 18, 22, 29, 35, 50, 96, 104, (byte) 0xFF },
			{ 56, 110, 123, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 1, 40, 76, 80, 94, 107, 118, (byte) 0xFF },
			{ 10, 21, 96, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 22, 26, 33, 39, 54, 100, 108, (byte) 0xFF },
			{ 60, 114, 127, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 5, 44, 80, 84, 98, 111, 122, (byte) 0xFF },
			{ 14, 25, 100, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 26, 30, 37, 43, 58, 104, 112, (byte) 0xFF },
			{ 3, 118, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF, (byte) 0xFF },
			{ 9, 48, 84, 88, 102, 115, 126, (byte) 0xFF },
			{ 18, 29, 104, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 30, 34, 41, 47, 62, 108, 116, (byte) 0xFF },
			{ 7, 122, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF, (byte) 0xFF },
			{ 2, 13, 52, 88, 92, 106, 119, (byte) 0xFF },
			{ 22, 33, 108, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 34, 38, 45, 51, 66, 112, 120, (byte) 0xFF },
			{ 11, 126, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF, (byte) 0xFF },
			{ 6, 17, 56, 92, 96, 110, 123, (byte) 0xFF },
			{ 26, 37, 112, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 38, 42, 49, 55, 70, 116, 124, (byte) 0xFF },
			{ 2, 15, 76, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 10, 21, 60, 96, 100, 114, 127, (byte) 0xFF },
			{ 30, 41, 116, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 0, 42, 46, 53, 59, 74, 120, (byte) 0xFF },
			{ 6, 19, 80, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 3, 14, 25, 100, 104, 118, (byte) 0xFF, (byte) 0xFF },
			{ 34, 45, 120, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 4, 46, 50, 57, 63, 78, 124, (byte) 0xFF },
			{ 10, 23, 84, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 7, 18, 29, 104, 108, 122, (byte) 0xFF, (byte) 0xFF },
			{ 38, 49, 124, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 0, 8, 50, 54, 61, 67, 82, (byte) 0xFF },
			{ 14, 27, 88, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 11, 22, 33, 108, 112, 126, (byte) 0xFF, (byte) 0xFF },
			{ 0, 42, 53, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 4, 12, 54, 58, 65, 71, 86, (byte) 0xFF },
			{ 18, 31, 92, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 2, 15, 26, 37, 76, 112, 116, (byte) 0xFF },
			{ 4, 46, 57, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 8, 16, 58, 62, 69, 75, 90, (byte) 0xFF },
			{ 22, 35, 96, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 6, 19, 30, 41, 80, 116, 120, (byte) 0xFF },
			{ 8, 50, 61, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 12, 20, 62, 66, 73, 79, 94, (byte) 0xFF },
			{ 26, 39, 100, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 10, 23, 34, 45, 84, 120, 124, (byte) 0xFF },
			{ 12, 54, 65, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 16, 24, 66, 70, 77, 83, 98, (byte) 0xFF },
			{ 30, 43, 104, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 0, 14, 27, 38, 49, 88, 124, (byte) 0xFF },
			{ 16, 58, 69, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 20, 28, 70, 74, 81, 87, 102, (byte) 0xFF },
			{ 34, 47, 108, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 0, 4, 18, 31, 42, 53, 92, (byte) 0xFF },
			{ 20, 62, 73, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 24, 32, 74, 78, 85, 91, 106, (byte) 0xFF },
			{ 38, 51, 112, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 4, 8, 22, 35, 46, 57, 96, (byte) 0xFF },
			{ 24, 66, 77, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 28, 36, 78, 82, 89, 95, 110, (byte) 0xFF },
			{ 42, 55, 116, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 8, 12, 26, 39, 50, 61, 100, (byte) 0xFF },
			{ 28, 70, 81, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 32, 40, 82, 86, 93, 99, 114, (byte) 0xFF },
			{ 46, 59, 120, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 12, 16, 30, 43, 54, 65, 104, (byte) 0xFF },
			{ 32, 74, 85, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 36, 90, 103, 118, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 50, 63, 124, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 16, 20, 34, 47, 58, 69, 108, (byte) 0xFF },
			{ 36, 78, 89, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 40, 94, 107, 122, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 0, 54, 67, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 20, 24, 38, 51, 62, 73, 112, (byte) 0xFF },
			{ 40, 82, 93, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 44, 98, 111, 126, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 4, 58, 71, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 24, 28, 42, 55, 66, 77, 116, (byte) 0xFF },
			{ 44, 86, 97, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 2, 48, 102, 115, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 8, 62, 75, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 28, 32, 46, 59, 70, 81, 120, (byte) 0xFF },
			{ 48, 90, 101, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 6, 52, 106, 119, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 12, 66, 79, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 32, 36, 50, 63, 74, 85, 124, (byte) 0xFF },
			{ 52, 94, 105, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 10, 56, 110, 123, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 16, 70, 83, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 0, 36, 40, 54, 67, 78, 89, (byte) 0xFF },
			{ 56, 98, 109, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 14, 60, 114, 127, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 20, 74, 87, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 4, 40, 44, 58, 71, 82, 93, (byte) 0xFF },
			{ 60, 102, 113, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 3, 18, 72, 114, 118, 125, (byte) 0xFF, (byte) 0xFF },
			{ 24, 78, 91, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 8, 44, 48, 62, 75, 86, 97, (byte) 0xFF },
			{ 64, 106, 117, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 1, 7, 22, 76, 118, 122, (byte) 0xFF, (byte) 0xFF },
			{ 28, 82, 95, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 12, 48, 52, 66, 79, 90, 101, (byte) 0xFF },
			{ 68, 110, 121, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 5, 11, 26, 80, 122, 126, (byte) 0xFF, (byte) 0xFF },
			{ 32, 86, 99, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF } };

	private static final byte[][] LTtableInverse = new byte[][] {
			{ 53, 55, 72, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 1, 5, 20, 90, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF },
			{ 15, 102, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF, (byte) 0xFF },
			{ 3, 31, 90, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 57, 59, 76, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 5, 9, 24, 94, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF },
			{ 19, 106, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF, (byte) 0xFF },
			{ 7, 35, 94, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 61, 63, 80, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 9, 13, 28, 98, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF },
			{ 23, 110, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF, (byte) 0xFF },
			{ 11, 39, 98, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 65, 67, 84, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 13, 17, 32, 102, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 27, 114, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF, (byte) 0xFF },
			{ 1, 3, 15, 20, 43, 102, (byte) 0xFF, (byte) 0xFF },
			{ 69, 71, 88, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 17, 21, 36, 106, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 1, 31, 118, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 5, 7, 19, 24, 47, 106, (byte) 0xFF, (byte) 0xFF },
			{ 73, 75, 92, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 21, 25, 40, 110, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 5, 35, 122, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 9, 11, 23, 28, 51, 110, (byte) 0xFF, (byte) 0xFF },
			{ 77, 79, 96, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 25, 29, 44, 114, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 9, 39, 126, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 13, 15, 27, 32, 55, 114, (byte) 0xFF, (byte) 0xFF },
			{ 81, 83, 100, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 1, 29, 33, 48, 118, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF },
			{ 2, 13, 43, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 1, 17, 19, 31, 36, 59, 118, (byte) 0xFF },
			{ 85, 87, 104, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 5, 33, 37, 52, 122, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF },
			{ 6, 17, 47, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 5, 21, 23, 35, 40, 63, 122, (byte) 0xFF },
			{ 89, 91, 108, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 9, 37, 41, 56, 126, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF },
			{ 10, 21, 51, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 9, 25, 27, 39, 44, 67, 126, (byte) 0xFF },
			{ 93, 95, 112, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 2, 13, 41, 45, 60, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF },
			{ 14, 25, 55, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 2, 13, 29, 31, 43, 48, 71, (byte) 0xFF },
			{ 97, 99, 116, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 6, 17, 45, 49, 64, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF },
			{ 18, 29, 59, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 6, 17, 33, 35, 47, 52, 75, (byte) 0xFF },
			{ 101, 103, 120, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF, (byte) 0xFF },
			{ 10, 21, 49, 53, 68, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF },
			{ 22, 33, 63, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 10, 21, 37, 39, 51, 56, 79, (byte) 0xFF },
			{ 105, 107, 124, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF, (byte) 0xFF },
			{ 14, 25, 53, 57, 72, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF },
			{ 26, 37, 67, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 14, 25, 41, 43, 55, 60, 83, (byte) 0xFF },
			{ 0, 109, 111, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 18, 29, 57, 61, 76, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF },
			{ 30, 41, 71, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 18, 29, 45, 47, 59, 64, 87, (byte) 0xFF },
			{ 4, 113, 115, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 22, 33, 61, 65, 80, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF },
			{ 34, 45, 75, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 22, 33, 49, 51, 63, 68, 91, (byte) 0xFF },
			{ 8, 117, 119, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 26, 37, 65, 69, 84, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF },
			{ 38, 49, 79, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 26, 37, 53, 55, 67, 72, 95, (byte) 0xFF },
			{ 12, 121, 123, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 30, 41, 69, 73, 88, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF },
			{ 42, 53, 83, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 30, 41, 57, 59, 71, 76, 99, (byte) 0xFF },
			{ 16, 125, 127, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 34, 45, 73, 77, 92, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF },
			{ 46, 57, 87, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 34, 45, 61, 63, 75, 80, 103, (byte) 0xFF },
			{ 1, 3, 20, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 38, 49, 77, 81, 96, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF },
			{ 50, 61, 91, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 38, 49, 65, 67, 79, 84, 107, (byte) 0xFF },
			{ 5, 7, 24, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 42, 53, 81, 85, 100, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF },
			{ 54, 65, 95, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 42, 53, 69, 71, 83, 88, 111, (byte) 0xFF },
			{ 9, 11, 28, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 46, 57, 85, 89, 104, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF },
			{ 58, 69, 99, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 46, 57, 73, 75, 87, 92, 115, (byte) 0xFF },
			{ 13, 15, 32, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 50, 61, 89, 93, 108, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF },
			{ 62, 73, 103, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 50, 61, 77, 79, 91, 96, 119, (byte) 0xFF },
			{ 17, 19, 36, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 54, 65, 93, 97, 112, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF },
			{ 66, 77, 107, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 54, 65, 81, 83, 95, 100, 123, (byte) 0xFF },
			{ 21, 23, 40, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 58, 69, 97, 101, 116, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF },
			{ 70, 81, 111, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 58, 69, 85, 87, 99, 104, 127, (byte) 0xFF },
			{ 25, 27, 44, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 62, 73, 101, 105, 120, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF },
			{ 74, 85, 115, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 3, 62, 73, 89, 91, 103, 108, (byte) 0xFF },
			{ 29, 31, 48, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 66, 77, 105, 109, 124, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF },
			{ 78, 89, 119, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 7, 66, 77, 93, 95, 107, 112, (byte) 0xFF },
			{ 33, 35, 52, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 0, 70, 81, 109, 113, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF },
			{ 82, 93, 123, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 11, 70, 81, 97, 99, 111, 116, (byte) 0xFF },
			{ 37, 39, 56, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 4, 74, 85, 113, 117, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF },
			{ 86, 97, 127, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 15, 74, 85, 101, 103, 115, 120, (byte) 0xFF },
			{ 41, 43, 60, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 8, 78, 89, 117, 121, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF },
			{ 3, 90, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF, (byte) 0xFF },
			{ 19, 78, 89, 105, 107, 119, 124, (byte) 0xFF },
			{ 45, 47, 64, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 12, 82, 93, 121, 125, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF },
			{ 7, 94, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF, (byte) 0xFF },
			{ 0, 23, 82, 93, 109, 111, 123, (byte) 0xFF },
			{ 49, 51, 68, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF },
			{ 1, 16, 86, 97, 125, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF },
			{ 11, 98, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF, (byte) 0xFF },
			{ 4, 27, 86, 97, 113, 115, 127, (byte) 0xFF } };

	private final int PHI = 0x9E3779B9;
	
	public SerpentCipher(byte[] key) {
		super("Serpent", key, null, "ECB", 16, 32);
	}
	
	public SerpentCipher(byte[] key, byte[] iv, String mode) {
		super("Serpent", key, iv, mode, 16, 32);
	}

	@Override
	protected byte[] decryptBlock(byte[] ciphertext) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	protected byte[] decryptionRound(byte[] roundBytes, int roundNumber) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	protected byte[] encryptBlock(byte[] plaintext) {
		int[][] Khat = new int[ROUNDS+1][4];
		for (int i = 0; i < ROUNDS + 1; i++) {
			for (int j = 0; j < 4; j++) {
				byte[] temp = new byte[4];
				System.arraycopy(roundKeys[i], 4*j, temp, 0, 4);
				Khat[i][j] = A9Utility.bytesToInt(temp);
			}
		}
		int[] X = {
				(plaintext[0] & 0xFF) | (plaintext[1] & 0xFF) << 8
						| (plaintext[2] & 0xFF) << 16
						| (plaintext[3] & 0xFF) << 24,
				(plaintext[4] & 0xFF) | (plaintext[5] & 0xFF) << 8
						| (plaintext[6] & 0xFF) << 16
						| (plaintext[7] & 0xFF) << 24,
				(plaintext[8] & 0xFF) | (plaintext[9] & 0xFF) << 8
						| (plaintext[10] & 0xFF) << 16
						| (plaintext[11] & 0xFF) << 24,
				(plaintext[12] & 0xFF) | (plaintext[13] & 0xFF) << 8
						| (plaintext[14] & 0xFF) << 16
						| (plaintext[15] & 0xFF) << 24 };
		int[] Bhat = IP(X);

		for (int i = 1; i < ROUNDS; i++) {
			Bhat = R(i, Bhat, Khat);
		}
		X = FP(Bhat);

		int a = X[0], b = X[1], c = X[2], d = X[3];
		byte[] ciphertext = { (byte) (a), (byte) (a >>> 8), (byte) (a >>> 16),
				(byte) (a >>> 24), (byte) (b), (byte) (b >>> 8),
				(byte) (b >>> 16), (byte) (b >>> 24), (byte) (c),
				(byte) (c >>> 8), (byte) (c >>> 16), (byte) (c >>> 24),
				(byte) (d), (byte) (d >>> 8), (byte) (d >>> 16),
				(byte) (d >>> 24) };
		return ciphertext;
	}

	@Override
	protected byte[] encryptionRound(byte[] roundBytes, int roundNumber) {
		// Unnecessary in this implementation
		return null;
	}

	@Override
	protected void makeRoundKeys() {
		// TODO Auto-generated method stub
		int[] w = new int[4 * (ROUNDS + 1)], k = new int[4 * (ROUNDS + 1)];
		int i, j, t;
		for (i = 0; i < key.length / 4; i++) {
			w[i] = (key[4 * i] & 0xFF) | (key[4 * i + 1] & 0xFF) << 8
					| (key[4 * i + 2] & 0xFF) << 16
					| (key[4 * i + 3] & 0xFF) << 24;
		}
		if (i < 8) {
			w[i++] = 1;
		}

		for (i = 8, j = 0; i < 16; i++) {
			t = w[j] ^ w[i - 5] ^ w[i - 3] ^ w[i - 1] ^ PHI ^ j++;
			w[i] = Integer.rotateLeft(t, 11);
		}
		for (i = 0, j = 8; i < 8; i++, j++) {
			w[i] = w[j];
		}

		for (; i < 4 * (ROUNDS + 1); i++) {
			t = w[i - 8] ^ w[i - 5] ^ w[i - 3] ^ w[i - 1] ^ PHI ^ i;
			w[i] = Integer.rotateLeft(t, 11);
		}

		int box, a, b, c, d, in, out;
		for (i = 0; i < ROUNDS + 1; i++) {
			box = (ROUNDS + 3 - i) % ROUNDS;
			a = w[4 * i];
			b = w[4 * i + 1];
			c = w[4 * i + 2];
			d = w[4 * i + 3];
			for (j = 0; j < 32; j++) {
				in = A9Utility.getBit(a, j) | A9Utility.getBit(b, j) << 1
						| A9Utility.getBit(c, j) << 2
						| A9Utility.getBit(d, j) << 3;
				out = S(box, in);
				k[4 * i] |= A9Utility.getBit(out, 0) << j;
				k[4 * i + 1] |= A9Utility.getBit(out, 1) << j;
				k[4 * i + 2] |= A9Utility.getBit(out, 2) << j;
				k[4 * i + 3] |= A9Utility.getBit(out, 3) << j;
			}
		}

		int[][] K = new int[ROUNDS + 1][4];
		roundKeys = new byte[ROUNDS + 1][16];
		for (i = 0; i < ROUNDS + 1; i++) {
			K[i][0] = k[4 * i];
			K[i][1] = k[4 * i + 1];
			K[i][2] = k[4 * i + 2];
			K[i][3] = k[4 * i + 3];
		}

		for (i = 0; i < ROUNDS + 1; i++) {
			K[i] = IP(K[i]);
		}

		for (i = 0; i < ROUNDS + 1; i++) {
			System.arraycopy(A9Utility.intToBytes(k[4 * i]), 0, roundKeys[i],
					0, 4);
			System.arraycopy(A9Utility.intToBytes(k[4 * i + 1]), 0,
					roundKeys[i], 4, 4);
			System.arraycopy(A9Utility.intToBytes(k[4 * i + 2]), 0,
					roundKeys[i], 8, 4);
			System.arraycopy(A9Utility.intToBytes(k[4 * i + 3]), 0,
					roundKeys[i], 12, 4);
		}
	}

	/**
	 * Encrypt exactly one block of plaintext.
	 * 
	 * @param in
	 *            The plaintext.
	 * @param inOffset
	 *            Index of in from which to start considering data.
	 * @param sessionKey
	 *            The session key to use for encryption.
	 * @return The ciphertext generated from a plaintext using the session key.
	 */
	public byte[] blockEncrypt(byte[] in, int inOffset, Object sessionKey) {
		int[][] Khat = (int[][]) sessionKey;
		int[] x = {
				(in[inOffset++] & 0xFF) | (in[inOffset++] & 0xFF) << 8
						| (in[inOffset++] & 0xFF) << 16
						| (in[inOffset++] & 0xFF) << 24,
				(in[inOffset++] & 0xFF) | (in[inOffset++] & 0xFF) << 8
						| (in[inOffset++] & 0xFF) << 16
						| (in[inOffset++] & 0xFF) << 24,
				(in[inOffset++] & 0xFF) | (in[inOffset++] & 0xFF) << 8
						| (in[inOffset++] & 0xFF) << 16
						| (in[inOffset++] & 0xFF) << 24,
				(in[inOffset++] & 0xFF) | (in[inOffset++] & 0xFF) << 8
						| (in[inOffset++] & 0xFF) << 16
						| (in[inOffset++] & 0xFF) << 24 };
		int[] Bhat = IP(x);
		for (int i = 0; i < ROUNDS; i++) {
			Bhat = R(i, Bhat, Khat);
		}
		x = FP(Bhat);

		int a = x[0], b = x[1], c = x[2], d = x[3];
		byte[] result = new byte[] { (byte) (a), (byte) (a >>> 8),
				(byte) (a >>> 16), (byte) (a >>> 24), (byte) (b),
				(byte) (b >>> 8), (byte) (b >>> 16), (byte) (b >>> 24),
				(byte) (c), (byte) (c >>> 8), (byte) (c >>> 16),
				(byte) (c >>> 24), (byte) (d), (byte) (d >>> 8),
				(byte) (d >>> 16), (byte) (d >>> 24) };
		return result;
	}

	/**
	 * Decrypt exactly one block of ciphertext.
	 * 
	 * @param in
	 *            The ciphertext.
	 * @param inOffset
	 *            Index of in from which to start considering data.
	 * @param sessionKey
	 *            The session key to use for decryption.
	 * @return The plaintext generated from a ciphertext using the session key.
	 */
	public byte[] blockDecrypt(byte[] in, int inOffset, Object sessionKey) {
		int[][] Khat = (int[][]) sessionKey;
		int[] x = {
				(in[inOffset++] & 0xFF) | (in[inOffset++] & 0xFF) << 8
						| (in[inOffset++] & 0xFF) << 16
						| (in[inOffset++] & 0xFF) << 24,
				(in[inOffset++] & 0xFF) | (in[inOffset++] & 0xFF) << 8
						| (in[inOffset++] & 0xFF) << 16
						| (in[inOffset++] & 0xFF) << 24,
				(in[inOffset++] & 0xFF) | (in[inOffset++] & 0xFF) << 8
						| (in[inOffset++] & 0xFF) << 16
						| (in[inOffset++] & 0xFF) << 24,
				(in[inOffset++] & 0xFF) | (in[inOffset++] & 0xFF) << 8
						| (in[inOffset++] & 0xFF) << 16
						| (in[inOffset++] & 0xFF) << 24 };
		int[] Bhat = FPinverse(x);
		for (int i = ROUNDS - 1; i >= 0; i--) {
			Bhat = Rinverse(i, Bhat, Khat);
		}
		x = IPinverse(Bhat);

		int a = x[0], b = x[1], c = x[2], d = x[3];
		byte[] result = new byte[] { (byte) (a), (byte) (a >>> 8),
				(byte) (a >>> 16), (byte) (a >>> 24), (byte) (b),
				(byte) (b >>> 8), (byte) (b >>> 16), (byte) (b >>> 24),
				(byte) (c), (byte) (c >>> 8), (byte) (c >>> 16),
				(byte) (c >>> 24), (byte) (d), (byte) (d >>> 8),
				(byte) (d >>> 16), (byte) (d >>> 24) };
		return result;
	}

	/**
	 * @return A 128-bit entity which is the result of applying the Initial
	 *         Permutation (IP) to a 128-bit entity <code>x</code>.
	 */
	private static int[] IP(int[] x) {
		return permutate(IPtable, x);
	}

	/**
	 * @return A 128-bit entity which is the result of applying the inverse of
	 *         the Initial Permutation to a 128-bit entity <code>x</code>.
	 */
	private static int[] IPinverse(int[] x) {
		return permutate(FPtable, x);
	}

	/**
	 * @return A 128-bit entity which is the result of applying the Final
	 *         Permutation (FP) to a 128-bit entity <code>x</code>.
	 */
	private static int[] FP(int[] x) {
		return permutate(FPtable, x);
	}

	/**
	 * @return A 128-bit entity which is the result of applying the inverse of
	 *         the Final Permutation to a 128-bit entity <code>x</code>.
	 */
	private static int[] FPinverse(int[] x) {
		return permutate(IPtable, x);
	}

	/**
	 * @return A 128-bit entity which is the result of applying a permutation
	 *         coded in a given table <code>T</code> to a 128-bit entity
	 *         <code>x</code>.
	 */
	private static int[] permutate(byte[] T, int[] x) {
		int[] result = new int[4];
		for (int i = 0; i < 128; i++)
			A9Utility.setBit(result, i, A9Utility.getBit(x, T[i] & 0x7F));
		return result;
	}

	/**
	 * @return A 128-bit entity as the result of XORing, bit-by-bit, two given
	 *         128-bit entities <code>x</code> and <code>y</code>.
	 */
	private static int[] xor128(int[] x, int[] y) {
		return new int[] { x[0] ^ y[0], x[1] ^ y[1], x[2] ^ y[2], x[3] ^ y[3] };
	}

	/**
	 * @return The nibble --a 4-bit entity-- obtained by applying a given S-box
	 *         to a 32-bit entity <code>x</code>.
	 */
	private static int S(int box, int x) {
		return Sbox[box][x] & 0x0F;
	}

	/**
	 * @return The nibble --a 4-bit entity-- obtained byapplying the inverse of
	 *         a given S-box to a 32-bit entity <code>x</code>.
	 */
	private static int Sinverse(int box, int x) {
		return SboxInverse[box][x] & 0x0F;
	}

	/**
	 * @return A 128-bit entity being the result of applying, in parallel, 32
	 *         copies of a given S-box to a 128-bit entity <code>x</code>.
	 */
	private static int[] Shat(int box, int[] x) {
		int[] result = new int[4];
		for (int i = 0; i < 4; i++)
			for (int nibble = 0; nibble < 8; nibble++)
				result[i] |= S(box, A9Utility.getNibble(x[i], nibble)) << (nibble * 4);
		return result;
	}

	/**
	 * @return A 128-bit entity being the result of applying, in parallel, 32
	 *         copies of the inverse of a given S-box to a 128-bit entity
	 *         <code>x</code>.
	 */
	private static int[] ShatInverse(int box, int[] x) {
		int[] result = new int[4];
		for (int i = 0; i < 4; i++)
			for (int nibble = 0; nibble < 8; nibble++)
				result[i] |= Sinverse(box, A9Utility.getNibble(x[i], nibble)) << (nibble * 4);
		return result;
	}

	/**
	 * @return A 128-bit entity being the result of applying the linear
	 *         transformation to a 128-bit entity <code>x</code>.
	 */
	private static int[] LT(int[] x) {
		return transform(LTtable, x);
	}

	/**
	 * @return A 128-bit entity being the result of applying the inverse of the
	 *         linear transformation to a 128-bit entity <code>x</code>.
	 */
	private static int[] LTinverse(int[] x) {
		return transform(LTtableInverse, x);
	}

	/**
	 * @return A 128-bit entity being the result of applying a transformation
	 *         coded in a table <code>T</code> to a 128-bit entity
	 *         <code>x</code>. Each row, of say index <code>i</code>, in
	 *         <code>T</code> indicates the bits from <code>x</code> to be XORed
	 *         together in order to produce the resulting bit at position
	 *         <code>i</code>.
	 */
	private static int[] transform(byte[][] T, int[] x) {
		int j, b;
		int[] result = new int[4];
		for (int i = 0; i < 128; i++) {
			b = 0;
			j = 0;
			while (T[i][j] != (byte) 0xFF) {
				b ^= A9Utility.getBit(x, T[i][j] & 0x7F);
				j++;
			}
			A9Utility.setBit(result, i, b);
		}
		return result;
	}

	/**
	 * @return the 128-bit entity as the result of applying the round function R
	 *         at round <code>i</code> to the 128-bit entity <code>Bhati</code>,
	 *         using the appropriate subkeys from <code>Khat</code>.
	 */
	private int[] R(int i, int[] Bhati, int[][] Khat) {
		int[] xored = xor128(Bhati, Khat[i]);
		int[] Shati = Shat(i, xored);
		int[] BhatiPlus1;
		if ((0 <= i) && (i <= ROUNDS - 2))
			BhatiPlus1 = LT(Shati);
		else if (i == ROUNDS - 1)
			BhatiPlus1 = xor128(Shati, Khat[ROUNDS]);
		else
			throw new RuntimeException("Round " + i + " is out of 0.."
					+ (ROUNDS - 1) + " range");
		return BhatiPlus1;
	}

	/**
	 * @return the 128-bit entity as the result of applying the inverse of the
	 *         round function R at round <code>i</code> to the 128-bit entity
	 *         <code>Bhati</code>, using the appropriate subkeys from
	 *         <code>Khat</code>.
	 */
	private int[] Rinverse(int i, int[] BhatiPlus1, int[][] Khat) {
		int[] Shati = new int[4];
		if ((0 <= i) && (i <= ROUNDS - 2))
			Shati = LTinverse(BhatiPlus1);
		else if (i == ROUNDS - 1)
			Shati = xor128(BhatiPlus1, Khat[ROUNDS]);
		else
			throw new RuntimeException("Round " + i + " is out of 0.."
					+ (ROUNDS - 1) + " range");
		int[] xored = ShatInverse(i, Shati);
		int[] Bhati = xor128(xored, Khat[i]);
		return Bhati;
	}

	private int[] Rinverse(int i, int[] BhatiPlus1, int[][] Khat, int in,
			int val) {
		int[] Shati = new int[4];
		if ((0 <= i) && (i <= ROUNDS - 2))
			Shati = LTinverse(BhatiPlus1);
		else if (i == ROUNDS - 1)
			Shati = xor128(BhatiPlus1, Khat[ROUNDS]);
		else
			throw new RuntimeException("Round " + i + " is out of 0.."
					+ (ROUNDS - 1) + " range");
		int[] xored = ShatInverse(i, Shati);
		if (i == in) {
			xored[0] = val | (val << 4);
			xored[0] |= (xored[0] << 8);
			xored[0] |= (xored[0] << 16);
			xored[1] = xored[2] = xored[3] = xored[0];
		}
		int[] Bhati = xor128(xored, Khat[i]);
		return Bhati;
	}
}
