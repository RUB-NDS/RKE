package de.rub.rke.test.fakealgorithmset.mockkukem;

import java.util.Arrays;

import de.rub.rke.brke.BrkeCiphertext;
import de.rub.rke.kukem.KuKemAssociatedData;
import de.rub.rke.kukem.KuKemPublicKey;
import de.rub.rke.test.Encoder;
import de.rub.rke.test.fakealgorithmset.mockvariables.MockAssociatedData;

/**
 * Implements the KuKemPublicKey for the mock kuKem.
 * 
 * Keys are identified by their id (int).
 * 
 * Updates are performed by saving the AdCiphertext which is passed to the
 * update function of the kuKem in an update array. Since all values are int
 * this is easily possible. This makes comparing updates also easy, because if
 * two keys were updated with the same Adciphertext their update arrays contain
 * the same ints.
 * 
 * @author Marco Smeets
 *
 */
public class MockKuKemPublicKey implements KuKemPublicKey {
	int id;
	int[] updates;

	public MockKuKemPublicKey(int id) {
		this.id = id;
		updates = new int[1];
		updates[0] = 0;
	}

	public MockKuKemPublicKey(int id, int[] updates) {
		this.id = id;
		this.updates = Arrays.copyOf(updates, updates.length);
	}

	public int getId() {
		return id;
	}

	/**
	 * Update saves the AdCiphertext in int representation in the updates array.
	 * 
	 * @param updateInfo
	 */
	public void update(KuKemAssociatedData updateInfo) {
		MockKuKemAssociatedData kuKemAssociatedData = (MockKuKemAssociatedData) updateInfo;
		MockAssociatedData ad = (MockAssociatedData) kuKemAssociatedData.getAssociatedData();
		BrkeCiphertext ciphertext = kuKemAssociatedData.getCiphertext();
		int[] encodedCiphertext = Encoder.encodeFakeBrkeCiphertext(ciphertext);
		int index = updates.length;
		if (index == 1) {
			updates = Arrays.copyOf(updates, updates.length + encodedCiphertext.length);
			updates[index - 1] = ad.getIntRepresentation();
			for (int i = 0; i < encodedCiphertext.length; i++) {
				updates[i + index] = encodedCiphertext[i];
			}
		} else {
			updates = Arrays.copyOf(updates, updates.length + encodedCiphertext.length + 1);
			updates[index] = ad.getIntRepresentation();
			for (int i = 0; i < encodedCiphertext.length; i++) {
				updates[i + index + 1] = encodedCiphertext[i];
			}
		}
	}

	public int[] getUpdateArray() {
		return updates;
	}

	/**
	 * @return object representation in int
	 */
	public int[] getIntEncoding() {
		int[] encoding = new int[updates.length + 1];
		encoding[0] = id;
		for (int i = 1; i < encoding.length; i++) {
			encoding[i] = updates[i - 1];
		}
		return encoding;
	}
}
