package de.rub.rke.test.fakealgorithmset.mockkukem;

import de.rub.rke.kukem.KuKemKeyPair;
import de.rub.rke.kukem.KuKemPublicKey;
import de.rub.rke.kukem.KuKemSecretKey;

/**
 * Implements KuKemKeyPair for the mock kuKem
 * 
 * @author Marco Smeets
 *
 */
public class MockKuKemKeyPair implements KuKemKeyPair {

	KuKemSecretKey secretKey;
	KuKemPublicKey publicKey;

	public MockKuKemKeyPair(int id) {
		this.secretKey = new MockKuKemSecretKey(id);
		this.publicKey = new MockKuKemPublicKey(id);
	}

	@Override
	public KuKemSecretKey getSecretKey() {
		// TODO Auto-generated method stub
		return secretKey;
	}

	@Override
	public KuKemPublicKey getPublicKey() {
		// TODO Auto-generated method stub
		return publicKey;
	}

}
