package de.rub.rke.queuedkukem;

import de.rub.rke.variables.SymmetricKey;

/**
 * Class that implements the Output produced by a QueuedKuKem
 * 
 * @author Marco Smeets
 *
 */
public class QueuedKuKemOutput {

	private SymmetricKey generatedKey;
	private QueuedKuKemCiphertext ciphertext;

	/**
	 * Constructor
	 * 
	 * @param generatedKey
	 * @param ciphertext
	 */
	public QueuedKuKemOutput(SymmetricKey generatedKey, QueuedKuKemCiphertext ciphertext) {
		this.generatedKey = generatedKey;
		this.ciphertext = ciphertext;
	}

	/**
	 * @return generated key
	 */
	public SymmetricKey getGeneratedKey() {
		return generatedKey;
	}

	/**
	 * @return queuedKuKemCiphertext
	 */
	public QueuedKuKemCiphertext getCiphertext() {
		return ciphertext;
	}
}
