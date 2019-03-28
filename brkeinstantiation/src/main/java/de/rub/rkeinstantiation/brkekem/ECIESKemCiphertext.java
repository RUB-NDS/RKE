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

	public ECIESKemCiphertext(byte[] ciphertext) {
		this.ciphertext = Arrays.copyOf(ciphertext, ciphertext.length);
	}

	public byte[] getCiphertext() {
		return ciphertext;
	}
}
