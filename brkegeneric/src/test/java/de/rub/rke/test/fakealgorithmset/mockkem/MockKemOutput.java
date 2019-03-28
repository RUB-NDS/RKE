package de.rub.rke.test.fakealgorithmset.mockkem;

import de.rub.rke.kem.KemCiphertext;
import de.rub.rke.kem.KemOutput;
import de.rub.rke.kem.KemPublicKey;
import de.rub.rke.test.fakealgorithmset.mockvariables.MockSymmetricKey;
import de.rub.rke.variables.SymmetricKey;

/**
 * Implementation of Kem Output for the mock Kem
 * 
 * @author Marco Smeets
 *
 */
public class MockKemOutput implements KemOutput {

	SymmetricKey key;
	KemCiphertext ciphertext;

	public MockKemOutput(int id, KemPublicKey publicKey) {
		key = new MockSymmetricKey(id);
		ciphertext = new MockKemCiphertext(publicKey, id);
	}

	@Override
	public SymmetricKey getKey() {
		return key;
	}

	@Override
	public KemCiphertext getCiphertext() {
		return ciphertext;
	}

}
