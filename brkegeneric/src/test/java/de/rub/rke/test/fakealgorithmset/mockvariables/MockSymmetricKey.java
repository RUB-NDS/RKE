package de.rub.rke.test.fakealgorithmset.mockvariables;

import de.rub.rke.variables.SymmetricKey;

/**
 * Implements SymmetricKey.
 * 
 * Also uses int to represent a key. If we need to mix two keys, we simply add
 * them.
 * 
 * @author Marco Smeets
 *
 */
public class MockSymmetricKey implements SymmetricKey {

	int id;

	public MockSymmetricKey(int id) {
		this.id = id;
	}

	public int getId() {
		return id;
	}

	@Override
	public void mixToKey(SymmetricKey key) {
		id += ((MockSymmetricKey) key).getId();
	}
}
