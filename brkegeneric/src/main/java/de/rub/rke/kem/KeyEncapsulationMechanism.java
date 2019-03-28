package de.rub.rke.kem;

import java.security.SecureRandom;

import de.rub.rke.variables.KeySeed;
import de.rub.rke.variables.SymmetricKey;

/**
 * Interface for a Key Encapsulating Mechanism (Kem)
 * 
 * 
 * @author Marco Smeets
 *
 */
public interface KeyEncapsulationMechanism {

	/**
	 * Generates a random key pair for a Kem
	 * 
	 * @return key pair for a Kem
	 */
	public KemKeyPair gen(SecureRandom randomness);

	/**
	 * Generates a key pair for a Kem dependent on a seed
	 * 
	 * @param seed - seed for key generation
	 * @return key pair for a Kem
	 */
	public KemKeyPair gen(KeySeed seed);

	/**
	 * Generates the public key for a Kem matching the secret key
	 * 
	 * @param secretKey - secret key for a Kem
	 * @return public key matching the secret key
	 */
	public KemPublicKey gen(KemSecretKey secretKey);

	/**
	 * Generates a random symmetric key and encrypts it with the public key
	 * 
	 * @param publicKey - public key used for encryption
	 * @return random symmetric key and encrypted symmetric key
	 */
	public KemOutput encapsulate(KemPublicKey publicKey);

	/**
	 * Decrypts the symmetric key
	 * 
	 * @param secretKey  - secret key used for decryption
	 * @param ciphertext - encrypted symmetric key
	 * @return symmetric key
	 */
	public SymmetricKey decapsulate(KemSecretKey secretKey, KemCiphertext ciphertext);

}