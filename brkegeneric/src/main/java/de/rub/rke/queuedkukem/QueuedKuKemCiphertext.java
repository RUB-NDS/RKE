package de.rub.rke.queuedkukem;

import java.util.LinkedList;
import java.util.Queue;

import de.rub.rke.kem.KemCiphertext;
import de.rub.rke.kukem.KuKemCiphertext;

/**
 * Class that implements the ciphertext produced by the QueuedKuKem.
 * 
 * @author Marco Smeets
 *
 */
public class QueuedKuKemCiphertext {

	private KemCiphertext kemCiphertext;
	private Queue<KuKemCiphertext> kuKemCiphertexts;

	/**
	 * Constructor
	 * 
	 * @param ciphertexts
	 */
	public QueuedKuKemCiphertext(KemCiphertext kemCiphertext, int numberOfEncapsulations,
			Queue<KuKemCiphertext> ciphertexts) {
		this.kemCiphertext = kemCiphertext;
		if (numberOfEncapsulations != 1) {
			this.kuKemCiphertexts = new LinkedList<KuKemCiphertext>(ciphertexts);
		} else {
			this.kuKemCiphertexts = null;
		}
	}

	public KemCiphertext getKemCiphertext() {
		return kemCiphertext;
	}

	/**
	 * @return ciphertext queue
	 */
	public Queue<KuKemCiphertext> getKuKemCiphertexts() {
		return kuKemCiphertexts;
	}
}
