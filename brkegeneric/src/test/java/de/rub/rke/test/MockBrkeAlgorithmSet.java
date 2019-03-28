package de.rub.rke.test;

import de.rub.rke.brke.BrkeAlgorithmSet;
import de.rub.rke.test.fakealgorithmset.factories.MockKemFactory;
import de.rub.rke.test.fakealgorithmset.factories.MockKuKemAssociatedDataFactory;
import de.rub.rke.test.fakealgorithmset.factories.MockKuKemFactory;
import de.rub.rke.test.fakealgorithmset.factories.MockRandomOracleFactory;
import de.rub.rke.test.fakealgorithmset.factories.MockSignatureFactory;
import de.rub.rke.test.fakealgorithmset.factories.MockTranscriptFactory;

/**
 * Implements the BrkeAlgorithmSet with the fake algorithms used for testing.
 * 
 * @author Marco Smeets
 *
 */
public class MockBrkeAlgorithmSet extends BrkeAlgorithmSet {

	public MockBrkeAlgorithmSet(MockKuKemFactory kuKemFactory, MockKemFactory kemFactory,
			MockRandomOracleFactory randomOracleFactory, MockKuKemAssociatedDataFactory associatedDataFactory,
			MockSignatureFactory signatureFactory, MockTranscriptFactory transcriptFactory) {
		super(kuKemFactory, kemFactory, randomOracleFactory, associatedDataFactory, signatureFactory,
				transcriptFactory);
	}

}
