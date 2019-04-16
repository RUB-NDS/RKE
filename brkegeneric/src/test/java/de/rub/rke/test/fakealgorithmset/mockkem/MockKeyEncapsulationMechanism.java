package de.rub.rke.test.fakealgorithmset.mockkem;

import java.security.SecureRandom;

import de.rub.rke.kem.KemCiphertext;
import de.rub.rke.kem.KemKeyPair;
import de.rub.rke.kem.KemOutput;
import de.rub.rke.kem.KemPublicKey;
import de.rub.rke.kem.KemSecretKey;
import de.rub.rke.kem.KeyEncapsulationMechanism;
import de.rub.rke.test.fakealgorithmset.mockvariables.MockKeySeed;
import de.rub.rke.test.fakealgorithmset.mockvariables.MockSymmetricKey;
import de.rub.rke.variables.KeySeed;
import de.rub.rke.variables.SymmetricKey;

/**
 * Implementation of a Kem. Uses int to identify keys. Provides no security and
 * is only used for testing. Encapsulating/Decapsulating only checks for
 * matching inputs.
 * 
 * @author Marco Smeets
 *
 */
public class MockKeyEncapsulationMechanism implements KeyEncapsulationMechanism {

	SecureRandom randomness;

	public MockKeyEncapsulationMechanism(SecureRandom randomness) {
		this.randomness = randomness;
	}

	@Override
	public KemKeyPair gen(SecureRandom randomness) {
		return new MockKemKeyPair(randomness.nextInt());
	}

	@Override
	public KemKeyPair gen(KeySeed seed) {
		return new MockKemKeyPair(((MockKeySeed) seed).getSeed());
	}

	@Override
	public KemPublicKey gen(KemSecretKey secretKey) {
		return new MockKemPublicKey(((MockKemSecretKey) secretKey).getId());
	}

	@Override
	public KemOutput encapsulate(KemPublicKey publicKey) {
		int keyid = randomness.nextInt();
		return new MockKemOutput(keyid, publicKey);
	}

	@Override
	public SymmetricKey decapsulate(KemSecretKey secretKey, KemCiphertext ciphertext) {
		MockKemCiphertext mockCiphertext = (MockKemCiphertext) ciphertext;
		if (((MockKemSecretKey) secretKey).getId() == ((MockKemPublicKey) mockCiphertext.getEncryptionKey()).getId()) {
			return new MockSymmetricKey(mockCiphertext.getKeyId());
		} else {
			return null;
		}
	}

}
