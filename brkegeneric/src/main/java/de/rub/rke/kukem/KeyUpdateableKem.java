package de.rub.rke.kukem;

import java.security.SecureRandom;

import de.rub.rke.variables.KeySeed;
import de.rub.rke.variables.SymmetricKey;

/**
 * Interface for a key-updateable Kem (kuKem) algorithm.
 * 
 * @author Marco Smeets
 *
 */
public interface KeyUpdateableKem {

	/**
	 * Generate a random key pair for a kuKem
	 * 
	 * @param randomness randomness used for key generation
	 * @return
	 */
	public KuKemKeyPair gen(SecureRandom randomness);

	/**
	 * Generate a key pair for a kuKem depending on the seed
	 * 
	 * @param seed
	 * @return
	 */
	public KuKemKeyPair gen(KeySeed seed);

	/**
	 * Generate a public key for a kuKem matching the secret key
	 * 
	 * @param secretKey
	 * @return
	 */
	public KuKemPublicKey gen(KuKemSecretKey secretKey);

	/**
	 * Updates the public key depending on the associated data.
	 * 
	 * @param publicKey
	 * @param associatedData
	 * @return
	 */
	public KuKemPublicKey updatePublicKey(KuKemPublicKey publicKey, KuKemAssociatedData associatedData);

	/**
	 * Update the secret key depending on the associated data.
	 * 
	 * @param secretKey
	 * @param associatedData
	 * @return
	 */
	public KuKemSecretKey updateSecretKey(KuKemSecretKey secretKey, KuKemAssociatedData associatedData);

	/**
	 * Generates a random symmetric key and encrypts it with the public key
	 * 
	 * @param publicKey
	 * @return
	 */
	public KuKemOutput encapsulate(KuKemPublicKey publicKey);

	/**
	 * Decapsulates the symmetric key
	 * 
	 * @param secretKey
	 * @param ciphertext
	 * @return
	 */
	public SymmetricKey decapsulate(KuKemSecretKey secretKey, KuKemCiphertext ciphertext);
}
