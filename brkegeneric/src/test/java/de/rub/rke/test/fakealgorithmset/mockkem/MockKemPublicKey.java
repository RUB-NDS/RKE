package de.rub.rke.test.fakealgorithmset.mockkem;

import de.rub.rke.kem.KemPublicKey;

/**
 * Implementation of the KemPublicKey for the mock Kem
 * 
 * @author Marco Smeets
 *
 */
public class MockKemPublicKey implements KemPublicKey {

	int id;

	public MockKemPublicKey(int id) {
		this.id = id;
	}

	public int getId() {
		return id;
	}
}
