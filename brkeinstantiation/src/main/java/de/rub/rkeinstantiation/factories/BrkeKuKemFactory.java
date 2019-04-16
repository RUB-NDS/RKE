package de.rub.rkeinstantiation.factories;

import java.security.SecureRandom;

import de.rub.rke.factories.KuKemFactory;
import de.rub.rke.kukem.KeyUpdateableKem;
import de.rub.rkeinstantiation.brkekukem.BrkeKuKem;

/**
 * Factory for the BrkeKuKem.
 * 
 * @author Marco Smeets
 *
 */
public class BrkeKuKemFactory implements KuKemFactory {

	/**
	 * Specifies the Size of the identity data. Has to match with the size of the
	 * BrkeKuKemAssociatedData.
	 */
	private final int IDENTITIY_SIZE = 32;

	@Override
	public KeyUpdateableKem createKuKemAlgorithm() {
		SecureRandom randomness = new SecureRandom();
		return new BrkeKuKem(randomness, IDENTITIY_SIZE);
	}

}
