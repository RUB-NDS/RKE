package de.rub.rkeinstantiation.variables;

import java.util.Arrays;

import de.rub.rke.variables.SymmetricKey;
import de.rub.rkeinstantiation.utility.SymmetricKeyCombiner;

/**
 * Class for the SymmetricKey used by the Brke construction.
 * 
 * @author Marco Smeets
 *
 */
public class BrkeSymmetricKey implements SymmetricKey {

	byte[] key;

	public BrkeSymmetricKey(byte[] key) {
		this.key = Arrays.copyOf(key, key.length);
	}

	public byte[] getKeyBytes() {
		return key;
	}

	@Override
	public void mixToKey(SymmetricKey key) {
		this.key = SymmetricKeyCombiner.mixKeys(this.key, ((BrkeSymmetricKey) key).getKeyBytes());
	}
}
