package de.rub.rkeinstantiation.variables;

import java.util.Arrays;

import de.rub.rke.variables.KeySeed;

/**
 * Class for the KeySeeds used in the Brke construction.
 * 
 * @author Marco Smeets
 *
 */
public class BrkeKeySeed implements KeySeed {

	byte[] seed;

	public BrkeKeySeed(byte[] seed) {
		this.seed = Arrays.copyOf(seed, seed.length);
	}

	@Override
	public byte[] getSeedAsByte() {
		return seed;
	}

}
