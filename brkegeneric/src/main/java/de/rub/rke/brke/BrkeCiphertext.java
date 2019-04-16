package de.rub.rke.brke;

import de.rub.rke.kukem.KuKemPublicKey;
import de.rub.rke.queuedkukem.QueuedKuKemCiphertext;
import de.rub.rke.signature.SignatureManager;
import de.rub.rke.signature.SignatureOutput;
import de.rub.rke.signature.SignatureVerificationKey;
import de.rub.rke.variables.AssociatedData;

/**
 * Class for the BRKE ciphertext
 * 
 * @author Marco Smeets
 *
 */
public class BrkeCiphertext {

	private int numberOfReceivedMessages;
	private KuKemPublicKey publicKey;
	private SignatureVerificationKey verificationKey;
	private int numberOfUsedKeys;
	private QueuedKuKemCiphertext ciphertext;
	private SignatureOutput signature;

	/**
	 * We need a empty constructor to reconstruct the objects from JSON.
	 */
	@SuppressWarnings("unused")
	private BrkeCiphertext() {
	}

	/**
	 * Constructor
	 * 
	 * @param numberOfReceivedMessages
	 * @param publicKey
	 * @param verificationKey
	 */
	public BrkeCiphertext(int numberOfReceivedMessages, KuKemPublicKey publicKey,
			SignatureVerificationKey verificationKey, int numberOfUsedKeys, QueuedKuKemCiphertext ciphertext) {
		this.numberOfReceivedMessages = numberOfReceivedMessages;
		this.publicKey = publicKey;
		this.verificationKey = verificationKey;
		this.numberOfUsedKeys = numberOfUsedKeys;
		this.ciphertext = ciphertext;
	}

	/**
	 * Computes the signature
	 * 
	 * @param signature
	 */
	public void computeSignature(SignatureManager signatureAlgorithm, AssociatedData ad) {
		this.signature = signatureAlgorithm.sign(ad, numberOfReceivedMessages, publicKey, verificationKey,
				numberOfUsedKeys, ciphertext);
	}

	/**
	 * @return r (number of received messages)
	 */
	public int getNumberOfReceivedMessages() {
		return numberOfReceivedMessages;
	}

	/**
	 * @return kuKem public key
	 */
	public KuKemPublicKey getPublicKey() {
		return publicKey;
	}

	/**
	 * @return verification key
	 */
	public SignatureVerificationKey getVerificationKey() {
		return verificationKey;
	}

	/**
	 * @return numberOfUsedKeys
	 */
	public int getNumberOfUsedKeys() {
		return numberOfUsedKeys;
	}

	/**
	 * @return ciphertext
	 */
	public QueuedKuKemCiphertext getCiphertext() {
		return ciphertext;
	}

	/**
	 * @return signature
	 */
	public SignatureOutput getSignature() {
		return signature;
	}
}
