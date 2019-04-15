package de.rub.rke.factories;

import de.rub.rke.signature.SignatureManager;

/**
 * Factory for the Signature
 * 
 * @author Marco Smeets
 *
 */
public interface SignatureFactory {

	/**
	 * Function that returns a Signature
	 * 
	 * @return Signature object
	 */
	public SignatureManager createSignatureManager();
}
