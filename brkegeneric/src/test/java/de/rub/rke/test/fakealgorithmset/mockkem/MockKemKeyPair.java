package de.rub.rke.test.fakealgorithmset.mockkem;

import de.rub.rke.kem.KemKeyPair;
import de.rub.rke.kem.KemPublicKey;
import de.rub.rke.kem.KemSecretKey;

/**
 * Implementation of KemKeyPair for the mock Kem
 * 
 * @author Marco Smeets
 *
 */
public class MockKemKeyPair implements KemKeyPair {

	private KemSecretKey secretKey;
	private KemPublicKey publicKey;

	public MockKemKeyPair(int id) {
		this.secretKey = new MockKemSecretKey(id);
		this.publicKey = new MockKemPublicKey(id);
	}

	public KemSecretKey getSecretKey() {
		return secretKey;
	}

	public KemPublicKey getPublicKey() {
		return publicKey;
	}
}
