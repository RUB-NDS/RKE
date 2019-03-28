package de.rub.rke.test.fakealgorithmset.mockvariables;

import de.rub.rke.variables.KeySeed;

/**
 * Implements Key Seed.
 * 
 * Uses int to represent the seed, as every other mock class.
 * 
 * @author Marco Smeets
 *
 */
public class MockKeySeed implements KeySeed {

	int seed;

	public MockKeySeed(int seed) {
		this.seed = seed;
	}

	public int getSeed() {
		return seed;
	}

	@Override
	public byte[] getSeedAsByte() {

		return null;
	}
}
