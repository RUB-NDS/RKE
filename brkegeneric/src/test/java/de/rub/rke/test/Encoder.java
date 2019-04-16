package de.rub.rke.test;

import java.util.LinkedList;
import java.util.Queue;

import de.rub.rke.brke.BrkeCiphertext;
import de.rub.rke.kukem.KuKemCiphertext;
import de.rub.rke.queuedkukem.QueuedKuKemCiphertext;
import de.rub.rke.test.fakealgorithmset.mockkem.MockKemCiphertext;
import de.rub.rke.test.fakealgorithmset.mockkukem.MockKuKemCiphertext;
import de.rub.rke.test.fakealgorithmset.mockkukem.MockKuKemPublicKey;
import de.rub.rke.test.fakealgorithmset.mocksignature.MockSignatureOutput;
import de.rub.rke.test.fakealgorithmset.mocksignature.MockSignatureVerificationKey;

/**
 * Since a fake BrkeCiphertext contains of several objects and every object
 * consists of int, we wrote an utiliy class that encodes a BrkeCiphertext to an
 * int array. This makes it easier to save and work with.
 * 
 * @author Marco Smeets
 *
 */
public class Encoder {

	/**
	 * Encodes a complete fake BrkeCiphertext to an int array.
	 * 
	 * @param ciphertext
	 * @return
	 */
	public static int[] encodeFakeBrkeCiphertext(BrkeCiphertext ciphertext) {
		int receivedMessages = ciphertext.getNumberOfReceivedMessages();
		MockKuKemPublicKey kuKemPublicKey = (MockKuKemPublicKey) ciphertext.getPublicKey();
		MockSignatureVerificationKey signaturePublicKey = (MockSignatureVerificationKey) ciphertext
				.getVerificationKey();
		int epoch = ciphertext.getNumberOfUsedKeys();
		QueuedKuKemCiphertext queueCiphertext = ciphertext.getCiphertext();
		MockKemCiphertext kemCiphertext = (MockKemCiphertext) queueCiphertext.getKemCiphertext();
		if (queueCiphertext.getKuKemCiphertexts() != null) {
			Queue<KuKemCiphertext> ciphertexts = new LinkedList<KuKemCiphertext>(queueCiphertext.getKuKemCiphertexts());
			MockSignatureOutput signature = (MockSignatureOutput) ciphertext.getSignature();

			int index = 0;

			int[] encodedKuKemPublicKey = kuKemPublicKey.getIntEncoding();
			int[] encodedSignature = signature.getIntEncoding();

			int[] encoding = new int[5 + encodedKuKemPublicKey.length + encodedSignature.length
					+ (ciphertexts.size() * 2)];
			encoding[index] = receivedMessages;
			index++;
			for (int i = index; i < encodedKuKemPublicKey.length + 1; i++) {
				encoding[i] = encodedKuKemPublicKey[i - index];
			}
			index += encodedKuKemPublicKey.length;
			encoding[index] = signaturePublicKey.getId();
			index++;
			encoding[index] = epoch;
			index++;
			encoding[index] = kemCiphertext.getIntEncoding()[0];
			index++;
			encoding[index] = kemCiphertext.getIntEncoding()[1];
			index++;
			while (!ciphertexts.isEmpty()) {
				MockKuKemCiphertext currentCiphertext = (MockKuKemCiphertext) ciphertexts.remove();
				encoding[index] = currentCiphertext.getIntEncoding()[0];
				index++;
				encoding[index] = currentCiphertext.getIntEncoding()[1];
				index++;
			}

			for (int i = index; i < index + encodedSignature.length; i++) {
				encoding[i] = encodedSignature[i - index];
			}
			return encoding;
		} else {
			MockSignatureOutput signature = (MockSignatureOutput) ciphertext.getSignature();

			int index = 0;

			int[] encodedKuKemPublicKey = kuKemPublicKey.getIntEncoding();
			int[] encodedSignature = signature.getIntEncoding();

			int[] encoding = new int[5 + encodedKuKemPublicKey.length + encodedSignature.length];
			encoding[index] = receivedMessages;
			index++;
			for (int i = index; i < encodedKuKemPublicKey.length + 1; i++) {
				encoding[i] = encodedKuKemPublicKey[i - index];
			}
			index += encodedKuKemPublicKey.length;
			encoding[index] = signaturePublicKey.getId();
			index++;
			encoding[index] = epoch;
			index++;
			encoding[index] = kemCiphertext.getIntEncoding()[0];
			index++;
			encoding[index] = kemCiphertext.getIntEncoding()[1];
			index++;
			for (int i = index; i < index + encodedSignature.length; i++) {
				encoding[i] = encodedSignature[i - index];
			}
			return encoding;
		}
	}

	/**
	 * Encodes a fake BrkeCiphertext for signing. So we ignore the signature part of
	 * the BrkeCiphertext in this function.
	 * 
	 * @param ciphertext
	 * @return
	 */
	public static int[] encodeFakeBrkeCiphertextForSign(BrkeCiphertext ciphertext) {
		int receivedMessages = ciphertext.getNumberOfReceivedMessages();
		MockKuKemPublicKey kuKemPublicKey = (MockKuKemPublicKey) ciphertext.getPublicKey();
		MockSignatureVerificationKey signaturePublicKey = (MockSignatureVerificationKey) ciphertext
				.getVerificationKey();
		int epoch = ciphertext.getNumberOfUsedKeys();
		QueuedKuKemCiphertext queueCiphertext = ciphertext.getCiphertext();
		MockKemCiphertext kemCiphertext = (MockKemCiphertext) queueCiphertext.getKemCiphertext();
		if (queueCiphertext.getKuKemCiphertexts() != null) {
			Queue<KuKemCiphertext> ciphertexts = new LinkedList<KuKemCiphertext>(queueCiphertext.getKuKemCiphertexts());

			int index = 0;

			int[] encodedKuKemPublicKey = kuKemPublicKey.getIntEncoding();

			int[] encoding = new int[5 + encodedKuKemPublicKey.length + (ciphertexts.size() * 2)];
			encoding[index] = receivedMessages;
			index++;
			for (int i = index; i < encodedKuKemPublicKey.length + 1; i++) {
				encoding[i] = encodedKuKemPublicKey[i - index];
			}
			index += encodedKuKemPublicKey.length;
			encoding[index] = signaturePublicKey.getId();
			index++;
			encoding[index] = epoch;
			index++;
			encoding[index] = kemCiphertext.getIntEncoding()[0];
			index++;
			encoding[index] = kemCiphertext.getIntEncoding()[1];
			index++;
			while (!ciphertexts.isEmpty()) {
				MockKuKemCiphertext currentCiphertext = (MockKuKemCiphertext) ciphertexts.remove();
				encoding[index] = currentCiphertext.getIntEncoding()[0];
				index++;
				encoding[index] = currentCiphertext.getIntEncoding()[1];
				index++;
			}
			return encoding;
		} else {
			int index = 0;

			int[] encodedKuKemPublicKey = kuKemPublicKey.getIntEncoding();

			int[] encoding = new int[5 + encodedKuKemPublicKey.length];
			encoding[index] = receivedMessages;
			index++;
			for (int i = index; i < encodedKuKemPublicKey.length + 1; i++) {
				encoding[i] = encodedKuKemPublicKey[i - index];
			}
			index += encodedKuKemPublicKey.length;
			encoding[index] = signaturePublicKey.getId();
			index++;
			encoding[index] = epoch;
			index++;
			encoding[index] = kemCiphertext.getIntEncoding()[0];
			index++;
			encoding[index] = kemCiphertext.getIntEncoding()[1];
			index++;
			return encoding;
		}
	}

}
