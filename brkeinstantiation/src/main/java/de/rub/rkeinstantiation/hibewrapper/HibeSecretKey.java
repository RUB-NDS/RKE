package de.rub.rkeinstantiation.hibewrapper;

import java.util.Arrays;

/**
 * Secret Key of the HIBE.
 * 
 * @author Marco Smeets
 *
 */
public class HibeSecretKey {

	private byte[] encodedHibeSecretKey;
	private byte[] encapsulationKey;

	public HibeSecretKey(byte[] encodedHibeSecretKey, byte[] encapsulationKey) {
		this.encodedHibeSecretKey = Arrays.copyOf(encodedHibeSecretKey, encodedHibeSecretKey.length);
		this.encapsulationKey = Arrays.copyOf(encapsulationKey, encapsulationKey.length);
	}

	public byte[] getEncodedHibeSecretKey() {
		return encodedHibeSecretKey;
	}

	public byte[] getEncapsulationKey() {
		return encapsulationKey;
	}
}
