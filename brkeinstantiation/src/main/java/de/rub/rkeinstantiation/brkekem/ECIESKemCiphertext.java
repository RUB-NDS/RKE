package de.rub.rkeinstantiation.brkekem;

import java.util.Arrays;

import de.rub.rke.kem.KemCiphertext;

/**
 * Ciphertext class for the ECIES Kem.
 * 
 * @author Marco Smeets
 *
 */
public class ECIESKemCiphertext implements KemCiphertext {

	private byte[] ciphertext;

	/**
	 * We need a empty constructor to reconstruct the objects from JSON.
	 */
	@SuppressWarnings("unused")
	private ECIESKemCiphertext() {
	}

	public ECIESKemCiphertext(byte[] ciphertext) {
		this.ciphertext = Arrays.copyOf(ciphertext, ciphertext.length);
	}

	public byte[] getCiphertext() {
		return ciphertext;
	}
}
