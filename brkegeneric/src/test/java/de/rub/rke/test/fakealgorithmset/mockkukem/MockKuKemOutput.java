package de.rub.rke.test.fakealgorithmset.mockkukem;

import de.rub.rke.kukem.KuKemCiphertext;
import de.rub.rke.kukem.KuKemOutput;
import de.rub.rke.kukem.KuKemPublicKey;
import de.rub.rke.test.fakealgorithmset.mockvariables.MockSymmetricKey;
import de.rub.rke.variables.SymmetricKey;

/**
 * Implements KuKemOutput for the mock kuKem.
 * 
 * @author Marco Smeets
 *
 */
public class MockKuKemOutput implements KuKemOutput {

	SymmetricKey key;
	KuKemCiphertext ciphertext;

	public MockKuKemOutput(int id, KuKemPublicKey publicKey) {
		key = new MockSymmetricKey(id);
		ciphertext = new MockKuKemCiphertext(publicKey, id);
	}

	@Override
	public SymmetricKey getKey() {
		return key;
	}

	@Override
	public KuKemCiphertext getCiphertext() {
		return ciphertext;
	}

}
