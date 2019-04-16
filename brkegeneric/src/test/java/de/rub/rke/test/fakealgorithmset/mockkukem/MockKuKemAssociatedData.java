package de.rub.rke.test.fakealgorithmset.mockkukem;

import de.rub.rke.brke.BrkeCiphertext;
import de.rub.rke.kukem.KuKemAssociatedData;
import de.rub.rke.variables.AssociatedData;

/**
 * Implementation of the associated data for the mock kuKem.
 * 
 * @author Marco Smeets
 *
 */
public class MockKuKemAssociatedData implements KuKemAssociatedData {

	private BrkeCiphertext ciphertext;
	private AssociatedData associatedData;

	public MockKuKemAssociatedData(AssociatedData associatedData, BrkeCiphertext ciphertext) {
		this.associatedData = associatedData;
		this.ciphertext = ciphertext;
	}

	public BrkeCiphertext getCiphertext() {
		return ciphertext;
	}

	public AssociatedData getAssociatedData() {
		return associatedData;
	}
}
