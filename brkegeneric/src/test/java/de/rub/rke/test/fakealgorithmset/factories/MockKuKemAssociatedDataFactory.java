package de.rub.rke.test.fakealgorithmset.factories;

import de.rub.rke.brke.BrkeCiphertext;
import de.rub.rke.factories.KuKemAssociatedDataFactory;
import de.rub.rke.kukem.KuKemAssociatedData;
import de.rub.rke.test.fakealgorithmset.mockkukem.MockKuKemAssociatedData;
import de.rub.rke.variables.AssociatedData;

/**
 * Implementation of AssociatedDataFactory that returns a mock kuKem associated
 * Data
 * 
 * @author Marco Smeets
 *
 */
public class MockKuKemAssociatedDataFactory implements KuKemAssociatedDataFactory {

	@Override
	public KuKemAssociatedData createAssociatedData(AssociatedData ad, BrkeCiphertext ciphertext) {
		return new MockKuKemAssociatedData(ad, ciphertext);
	}

}
