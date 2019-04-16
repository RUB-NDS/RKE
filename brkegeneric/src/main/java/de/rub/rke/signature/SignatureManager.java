package de.rub.rke.signature;

import java.security.SecureRandom;

import de.rub.rke.brke.BrkeCiphertext;
import de.rub.rke.kukem.KuKemPublicKey;
import de.rub.rke.queuedkukem.QueuedKuKemCiphertext;
import de.rub.rke.variables.AssociatedData;
import de.rub.rke.variables.KeySeed;

/**
 * Interface for the signature manager used by the Brke construction. This class manages
 * the interaction between the BRKE construction and the signature algorithm.
 * 
 * The class saves a queue (at most two) signing keys, and the verification key
 * of the communication partner.
 * 
 * @author Marco Smeets
 *
 */
public interface SignatureManager {

	/**
	 * Initializes the Signature Algorithm.
	 * 
	 * @param randomness - randomness used for key generation
	 * @param initiator  - true (if initiator of conversation; false otherwise)
	 */
	public void init(SecureRandom randomness, boolean initiator);

	/**
	 * Generates a random key pair for a signature. Saves the signing key and puts
	 * out the verification key.
	 * 
	 * @param randomness - randomness used for key generation
	 * @return signature verification key
	 */
	public SignatureVerificationKey gen(SecureRandom randomness);

	/**
	 * Generates a random key pair for a signature. Saves the signing key and puts
	 * out the verification key.
	 * 
	 * @param seed - seed used for key generation
	 * @return
	 */
	public SignatureVerificationKey gen(KeySeed seed);

	/**
	 * Sets the verification key
	 * 
	 * @param verificationKey
	 */
	public void setVerificationKey(SignatureVerificationKey verificationKey);

	/**
	 * Is used in the BrkeCiphertext class and is used to compute the Signature over
	 * the Ciphertext
	 * 
	 * @param ad
	 * @param numberOfReceivedMessages
	 * @param publicKey
	 * @param verificationKey
	 * @param epoch
	 * @param ciphertext
	 * @return SignatureOutput(Signature)
	 */
	public SignatureOutput sign(AssociatedData ad, int numberOfReceivedMessages, KuKemPublicKey publicKey,
			SignatureVerificationKey verificationKey, int numberOfUsedKeys, QueuedKuKemCiphertext ciphertext);

	/**
	 * Verifies the Signature in the BrkeCiphertext
	 * 
	 * @param ad
	 * @param ciphertext
	 * @return 1 if Signature is valid, 0 otherwise
	 */
	public boolean verify(AssociatedData ad, BrkeCiphertext ciphertext);
}
