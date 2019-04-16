package de.rub.rke.test.fakealgorithmset.mockkukem;

import java.security.SecureRandom;
import java.util.Arrays;

import de.rub.rke.kukem.KeyUpdateableKem;
import de.rub.rke.kukem.KuKemAssociatedData;
import de.rub.rke.kukem.KuKemCiphertext;
import de.rub.rke.kukem.KuKemKeyPair;
import de.rub.rke.kukem.KuKemOutput;
import de.rub.rke.kukem.KuKemPublicKey;
import de.rub.rke.kukem.KuKemSecretKey;
import de.rub.rke.test.fakealgorithmset.mockvariables.*;
import de.rub.rke.variables.KeySeed;
import de.rub.rke.variables.SymmetricKey;

/**
 * Implementation of a kuKem. Uses int to identify keys. Provides no security
 * and is only used for testing. Encapsulating/Decapsulating only checks for
 * matching inputs.
 * 
 * @author Marco Smeets
 *
 */
public class MockKeyUpdateableKem implements KeyUpdateableKem {

	SecureRandom randomness;

	/**
	 * @param randomness - randomness used for symmetric key generation
	 */
	public MockKeyUpdateableKem(SecureRandom randomness) {
		this.randomness = randomness;
	}

	/**
	 * A key pair is identified by an int. If public key and secret key have the
	 * same identifier (id) then we say they are a pair.
	 */
	@Override
	public KuKemKeyPair gen(SecureRandom randomness) {
		int id = randomness.nextInt();
		return new MockKuKemKeyPair(id);
	}

	/**
	 * Generate a key pair given a FakeKeySeed
	 * 
	 * @param seed - FakeKeySeed
	 * @return
	 */
	@Override
	public KuKemKeyPair gen(KeySeed seed) {
		return new MockKuKemKeyPair(((MockKeySeed) seed).getSeed());
	}

	/**
	 * Generate a public key given a secret key. We just set the id of the public
	 * key to the id of the secret key.
	 */
	@Override
	public KuKemPublicKey gen(KuKemSecretKey secretKey) {
		return new MockKuKemPublicKey(((MockKuKemSecretKey) secretKey).getId());
	}

	/**
	 * Updates a public key given associatedData.
	 */
	@Override
	public KuKemPublicKey updatePublicKey(KuKemPublicKey publicKey, KuKemAssociatedData associatedData) {
		MockKuKemPublicKey updatedPublicKey = new MockKuKemPublicKey(((MockKuKemPublicKey) publicKey).getId(),
				((MockKuKemPublicKey) publicKey).getUpdateArray());
		updatedPublicKey.update(associatedData);
		return updatedPublicKey;
	}

	/**
	 * Updates a secret key given associatedData.
	 */
	@Override
	public KuKemSecretKey updateSecretKey(KuKemSecretKey secretKey, KuKemAssociatedData associatedData) {
		MockKuKemSecretKey updatedSecretKey = new MockKuKemSecretKey(((MockKuKemSecretKey) secretKey).getId(),
				((MockKuKemSecretKey) secretKey).getUpdateArray());
		updatedSecretKey.update(associatedData);
		return updatedSecretKey;
	}

	/**
	 * Generates a int, which is used to identify a specific key. And then saves the
	 * public key with the key id in a kuKemOutput object.
	 */
	@Override
	public KuKemOutput encapsulate(KuKemPublicKey publicKey) {
		int keyid = randomness.nextInt();
		return new MockKuKemOutput(keyid, publicKey);
	}

	/**
	 * Gets a secret key and a ciphertext. The ciphertext contains the public key
	 * used for 'encapsulation' and the generated keyid. If the secret key is the
	 * matching secret key for the public key, we return the generated keyid. Since
	 * we simulate a kuKem we have to take key updates into account, thus, we
	 * compare the update arrays of the keys.
	 */
	@Override
	public SymmetricKey decapsulate(KuKemSecretKey secretKey, KuKemCiphertext cipherText) {
		MockKuKemPublicKey encryptionKey = (MockKuKemPublicKey) ((MockKuKemCiphertext) cipherText).getEncryptionKey();
		MockKuKemSecretKey decryptionKey = (MockKuKemSecretKey) secretKey;
		if (encryptionKey.getId() == decryptionKey.getId()) {
			int[] updatesEncryptionKey = encryptionKey.getUpdateArray();
			int[] updatesDecryptionKey = decryptionKey.getUpdateArray();
			if (Arrays.equals(updatesEncryptionKey, updatesDecryptionKey)) {
				return new MockSymmetricKey(((MockKuKemCiphertext) cipherText).getKeyId());
			}
		}
		return null;
	}

}
