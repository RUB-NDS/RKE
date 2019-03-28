package de.rub.rke.brke;

import de.rub.rke.factories.KuKemFactory;
import de.rub.rke.factories.KemFactory;
import de.rub.rke.factories.KeyedRandomOracleFactory;
import de.rub.rke.factories.KuKemAssociatedDataFactory;
import de.rub.rke.factories.SignatureFactory;
import de.rub.rke.factories.TranscriptFactory;

/**
 * Class for the set of algorithms used in BRKE.
 * 
 * @author Marco Smeets
 *
 */
public abstract class BrkeAlgorithmSet {

	private KuKemFactory kuKemFactory;
	private KemFactory kemFactory;
	private KeyedRandomOracleFactory randomOracleFactory;
	private SignatureFactory signatureFactory;
	private TranscriptFactory transcriptFactory;
	private KuKemAssociatedDataFactory associatedDataFactory;

	/**
	 * Constructor
	 * 
	 * @param kuKemFactory
	 * @param randomOracle
	 * @param signatureFactory
	 * @param transcriptFactory
	 */
	public BrkeAlgorithmSet(KuKemFactory kuKemFactory, KemFactory kemFactory, KeyedRandomOracleFactory randomOracle,
			KuKemAssociatedDataFactory associatedDataFactory, SignatureFactory signatureFactory,
			TranscriptFactory transcriptFactory) {
		this.kuKemFactory = kuKemFactory;
		this.kemFactory = kemFactory;
		this.associatedDataFactory = associatedDataFactory;
		this.randomOracleFactory = randomOracle;
		this.signatureFactory = signatureFactory;
		this.transcriptFactory = transcriptFactory;
	}

	/**
	 * @return kuKem factory
	 */
	public KuKemFactory getKuKemFactory() {
		return kuKemFactory;
	}

	public KemFactory getKemFactory() {
		return kemFactory;
	}

	public KuKemAssociatedDataFactory getAssociatedDataFactory() {
		return associatedDataFactory;
	}

	/**
	 * @return random oracle factory
	 */
	public KeyedRandomOracleFactory getKeyedRandomOracleFactory() {
		return randomOracleFactory;
	}

	/**
	 * @return signature factory
	 */
	public SignatureFactory getSignatureFactory() {
		return signatureFactory;
	}

	/**
	 * @return transcript factory
	 */
	public TranscriptFactory getTranscriptFactory() {
		return transcriptFactory;
	}
}
