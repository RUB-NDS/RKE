package de.rub.rkeinstantiation.hibewrapper;

import java.util.Arrays;

/**
 * Output of the HIBE
 * 
 * @author Marco Smeets
 *
 */
public class HibeOutput {
	private byte[] generatedKey;
	private HibeCiphertext ciphertext;

	public HibeOutput(byte[] generatedKey, HibeCiphertext ciphertext) {
		this.generatedKey = Arrays.copyOf(generatedKey, generatedKey.length);
		this.ciphertext = ciphertext;
	}

	public byte[] getGeneratedKey() {
		return generatedKey;
	}

	public HibeCiphertext getCiphertext() {
		return ciphertext;
	}
}
