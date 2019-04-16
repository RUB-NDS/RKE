package de.rub.rke.kem;

/**
 * Interface for the key pair used for a Kem
 * 
 * @author Marco Smeets
 *
 */
public interface KemKeyPair {

	/**
	 * @return secret key for a Kem
	 */
	public KemSecretKey getSecretKey();

	/**
	 * @return public key for a Kem
	 */
	public KemPublicKey getPublicKey();
}
