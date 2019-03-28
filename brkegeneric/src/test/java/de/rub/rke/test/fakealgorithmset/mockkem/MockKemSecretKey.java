package de.rub.rke.test.fakealgorithmset.mockkem;

import de.rub.rke.kem.KemSecretKey;

/**
 * Implementation of KemSecretKey for the mock Kem
 * 
 * @author Marco Smeets
 *
 */
public class MockKemSecretKey implements KemSecretKey {

	int id;

	public MockKemSecretKey(int id) {
		this.id = id;
	}

	public int getId() {
		return id;
	}
}
