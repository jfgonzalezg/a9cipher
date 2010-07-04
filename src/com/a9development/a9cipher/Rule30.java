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

package com.a9development.a9cipher;

import java.io.Serializable;

public class Rule30 implements Serializable {
	
	private static final long serialVersionUID = 1L;
	
	private long seed;
	
	public Rule30() {
		this(System.currentTimeMillis());
	}
	
	public Rule30(long seed) {
		setSeed(seed);
	}
	
	protected synchronized long next(int bits) {
		boolean[] currentState = new boolean[66];
		boolean[] updatedState = new boolean[64];
		for (int i = 1; i < 65; i++) {
			currentState[i] = longToBits(seed)[i-1];
		}
		for (int i = 1; i < 65; i++) {
			if ((currentState[i-1] && !currentState[i] && !currentState[i+1])
					|| (!currentState[i-1] && currentState[i] && currentState[i+1])
					|| (!currentState[i-1] && currentState[i] && !currentState[i+1])
					|| (!currentState[i-1] && !currentState[i] && currentState[i+1])) {
				updatedState[i-1] = true;
			} else { updatedState[i-1] = false; }
		}
		try {
			seed = bitsToLong(updatedState);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}	
		return seed;
	}
	
	public int nextInt() {
		return (int) next(32);
	}
	
	public int nextInt(int n) {
		if (n > 0) {
			if ((n & -n) == n) {
				return (int) ((n * (long) next(31)) >> 31);
			}
			int bits, val;
			do {
				bits = (int) next(31);
				val = bits % n;
			} while (bits - val + (n - 1) < 0);
			return val;
		}
		throw new IllegalArgumentException();
	}
	
	public long nextLong() {
		return next(64);
	}
	
	private boolean[] longToBits(long L) {
		boolean[] bits = new boolean[64];
		for (int i = 0; i < 64; i++) {
			bits[i] = ((L >> i) % 2) != 0; 
		}
		return bits;
	}
	
	private long bitsToLong(boolean[] bits) throws Exception {
		if (bits.length > 64) {
			throw new Exception("too many bits!");
		} else {
			long L = 0;
			for (int i = 0; i < bits.length; i++) {
				L += (bits[i]?1:0) * Math.pow(2, i);
			}
			return L;
		}
	}
	
	public synchronized void setSeed(long seed) {
		this.seed = seed;
	}
}
