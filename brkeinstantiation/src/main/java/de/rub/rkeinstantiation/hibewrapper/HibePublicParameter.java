package de.rub.rkeinstantiation.hibewrapper;

import java.util.Arrays;

/**
 * Public Parameter of the HIBE.
 * 
 * @author Marco Smeets
 *
 */
public class HibePublicParameter {

	private byte[] encapsulationPublicParameter;
	private byte[] encodedHibePublicParameter;
	
	/**
	 * We need a empty constructor to reconstruct the objects from JSON.
	 */
	@SuppressWarnings("unused")
	private HibePublicParameter() {
	}

	public HibePublicParameter(byte[] encodedHibePublicParameter, byte[] encapsulationPublicParameter) {
		this.encapsulationPublicParameter = Arrays.copyOf(encapsulationPublicParameter, encapsulationPublicParameter.length);
		this.encodedHibePublicParameter = Arrays.copyOf(encodedHibePublicParameter, encodedHibePublicParameter.length);
	}

	public byte[] getEncodedHibePublicParameter() {
		return encodedHibePublicParameter;
	}

	public byte[] getEncapsulationPublicParameter() {
		return encapsulationPublicParameter;
	}
}
