package de.rub.rke.signature;

/**
 * Interface for the key pair used for a signature
 * 
 * @author Marco Smeets
 *
 */
public interface SignatureKeyPair {

	/**
	 * @return secret key for a signature
	 */
	public SignatureSigningKey getSigningKey();

	/**
	 * @return public key for a signature
	 */
	public SignatureVerificationKey getVerificationKey();
}
