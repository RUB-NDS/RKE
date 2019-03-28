package de.rub.rkeinstantiation.hibewrapper;

/**
 * Key pair of the HIBE
 * 
 * @author Marco Smeets
 *
 */
public class HibeKeyPair {
	private HibeSecretKey hibeSecretKey;
	private HibePublicParameter hibePublicParameter;

	public HibeKeyPair(HibeSecretKey hibeSecretKey, HibePublicParameter hibePublicParameter) {
		this.hibeSecretKey = hibeSecretKey;
		this.hibePublicParameter = hibePublicParameter;
	}

	public HibeSecretKey getHibeSecretKey() {
		return hibeSecretKey;
	}

	public HibePublicParameter getHibePublicParameter() {
		return hibePublicParameter;
	}
}
