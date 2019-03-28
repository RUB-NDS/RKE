package de.rub.rkeinstantiation.hibewrapper;

import java.util.Arrays;

/**
 * Public Parameter of the HIBE.
 * 
 * @author Marco Smeets
 *
 */
public class HibePublicParameter {

	private byte[] encapsulationKey;
	private byte[] encodedHibePublicParameter;

	public HibePublicParameter(byte[] encodedHibePublicParameter, byte[] encapsulationPublicParameter) {
		this.encapsulationKey = Arrays.copyOf(encapsulationPublicParameter, encapsulationPublicParameter.length);
		this.encodedHibePublicParameter = Arrays.copyOf(encodedHibePublicParameter, encodedHibePublicParameter.length);
	}

	public byte[] getEncodedPublicParameter() {
		return encodedHibePublicParameter;
	}

	public byte[] getEncapsulationPublicParameter() {
		return encapsulationKey;
	}
}
