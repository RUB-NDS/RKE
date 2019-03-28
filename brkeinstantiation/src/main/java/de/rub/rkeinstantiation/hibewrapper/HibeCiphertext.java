package de.rub.rkeinstantiation.hibewrapper;

import java.util.Arrays;

/**
 * Ciphertext produced by the HIBE.
 * 
 * @author Marco Smeets
 *
 */
public class HibeCiphertext {
	private byte[] com;
	private byte[] ciphertext;
	private byte[] mactag;

	public HibeCiphertext(byte[] com, byte[] ciphertext, byte[] mactag) {
		this.com = Arrays.copyOf(com, com.length);
		this.ciphertext = Arrays.copyOf(ciphertext, ciphertext.length);
		this.mactag = Arrays.copyOf(mactag, mactag.length);
	}

	public byte[] getCom() {
		return com;
	}

	public byte[] getCiphertext() {
		return ciphertext;
	}

	public byte[] getMacTag() {
		return mactag;
	}
}
