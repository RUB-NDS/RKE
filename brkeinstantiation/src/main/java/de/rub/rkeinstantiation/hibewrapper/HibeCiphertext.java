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
	private byte[] macTag;

	/**
	 * We need a empty constructor to reconstruct the objects from JSON.
	 */
	@SuppressWarnings("unused")
	private HibeCiphertext() {
	}

	public HibeCiphertext(byte[] com, byte[] ciphertext, byte[] macTag) {
		this.com = Arrays.copyOf(com, com.length);
		this.ciphertext = Arrays.copyOf(ciphertext, ciphertext.length);
		this.macTag = Arrays.copyOf(macTag, macTag.length);
	}

	public byte[] getCom() {
		return com;
	}

	public byte[] getCiphertext() {
		return ciphertext;
	}

	public byte[] getMacTag() {
		return macTag;
	}
}
