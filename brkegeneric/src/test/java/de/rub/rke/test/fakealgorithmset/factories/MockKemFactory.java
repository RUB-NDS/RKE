package de.rub.rke.test.fakealgorithmset.factories;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import de.rub.rke.factories.KemFactory;
import de.rub.rke.kem.KeyEncapsulationMechanism;
import de.rub.rke.test.fakealgorithmset.mockkem.MockKeyEncapsulationMechanism;

/**
 * Implementation of KemFactory that returns a mock Kem
 * 
 * @author Marco Smeets
 *
 */
public class MockKemFactory implements KemFactory {

	@Override
	public KeyEncapsulationMechanism createKem() {
		SecureRandom randomness = null;
		try {
			randomness = SecureRandom.getInstance("SHA1PRNG");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		byte[] seed = { 1, 2, 3, 4 };
		randomness.setSeed(seed);
		return new MockKeyEncapsulationMechanism(randomness);
	}
}
