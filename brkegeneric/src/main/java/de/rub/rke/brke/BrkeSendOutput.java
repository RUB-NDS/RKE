package de.rub.rke.brke;

import de.rub.rke.variables.SymmetricKey;

/**
 * Class for the Output of BRKE send and receive
 * 
 * @author Marco Smeets
 *
 */
public class BrkeSendOutput {

	private SymmetricKey sessionKey;
	private BrkeCiphertext ciphertext;

	/**
	 * @param sessionKey
	 * @param ciphertext
	 */
	public BrkeSendOutput(SymmetricKey sessionKey, BrkeCiphertext ciphertext) {
		this.sessionKey = sessionKey;
		this.ciphertext = ciphertext;
	}

	/**
	 * @return generated session key
	 */
	public SymmetricKey getSessionKey() {
		return sessionKey;
	}

	/**
	 * @return BRKE ciphertext
	 */
	public BrkeCiphertext getCiphertext() {
		return ciphertext;
	}
}
