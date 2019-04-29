package de.rub.brkeevaluation.seclevel100algorithms;

import de.rub.rke.brke.BrkeAlgorithmSet;

import de.rub.rkeinstantiation.factories.BrkeKuKemAssociatedDataFactory;
import de.rub.rkeinstantiation.factories.BrkeKuKemFactory;
import de.rub.rkeinstantiation.factories.BrkeTranscriptFactory;
import de.rub.rkeinstantiation.factories.ECIESKemFactory;
import de.rub.rkeinstantiation.factories.HKDFRandomOracleFactory;

/**
 * Test Algorithmset1 for 100Bit Security Level. Uses a diffie-hellman group
 * with estimated symmetric equivalent strength of 100Bit.
 * 
 * @author Marco Smeets
 */
public class AlgorithmSet100Bit extends BrkeAlgorithmSet {

	public AlgorithmSet100Bit(BrkeKuKemFactory kuKemFactory, ECIESKemFactory kemFactory,
			HKDFRandomOracleFactory randomOracle, BrkeKuKemAssociatedDataFactory associatedDataFactory,
			DLPChameleon100BitSignatureFactory signatureFactory, BrkeTranscriptFactory transcriptFactory) {
		super(kuKemFactory, kemFactory, randomOracle, associatedDataFactory, signatureFactory, transcriptFactory);
	}

}
