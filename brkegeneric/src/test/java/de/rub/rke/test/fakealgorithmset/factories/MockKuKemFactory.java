package de.rub.rke.test.fakealgorithmset.factories;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import de.rub.rke.factories.KuKemFactory;
import de.rub.rke.kukem.KeyUpdateableKem;
import de.rub.rke.test.fakealgorithmset.mockkukem.MockKeyUpdateableKem;

/**
 * Implementation of KuKemFactory that returns a mock kuKem
 * 
 * @author Marco Smeets
 *
 */
public class MockKuKemFactory implements KuKemFactory {

	@Override
	public KeyUpdateableKem createKuKemAlgorithm() {
		SecureRandom randomness = null;
		try {
			randomness = SecureRandom.getInstance("SHA1PRNG");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		byte[] seed = { 2, 3, 4, 5 };
		randomness.setSeed(seed);
		return new MockKeyUpdateableKem(randomness);
	}
}
