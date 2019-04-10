package de.rub.rkeinstantiation.brkekukem;

import java.security.SecureRandom;

import de.rub.rke.kukem.KeyUpdateableKem;
import de.rub.rke.kukem.KuKemAssociatedData;
import de.rub.rke.kukem.KuKemCiphertext;
import de.rub.rke.kukem.KuKemKeyPair;
import de.rub.rke.kukem.KuKemOutput;
import de.rub.rke.kukem.KuKemPublicKey;
import de.rub.rke.kukem.KuKemSecretKey;
import de.rub.rke.variables.KeySeed;
import de.rub.rke.variables.SymmetricKey;
import de.rub.rkeinstantiation.hibewrapper.Hibe;
import de.rub.rkeinstantiation.hibewrapper.HibeKeyPair;
import de.rub.rkeinstantiation.hibewrapper.HibeOutput;
import de.rub.rkeinstantiation.hibewrapper.HibeSecretKey;
import de.rub.rkeinstantiation.variables.BrkeSymmetricKey;

/**
 * Key-Updateable Kem Implementation using the LWHIBE with CCA transformation.
 * 
 * @author Marco Smeets
 *
 */
public class BrkeKuKem implements KeyUpdateableKem {

	/**
	 * Identity size might be changed.
	 */
	private Hibe hibeAlgorithm;
	private SecureRandom randomness;
	private int identitySize;

	/**
	 * Constructs a kuKem.
	 * 
	 * @param randomness   - internal randomness to generate keys.
	 * @param identitySize - Size of the identity Data
	 */
	public BrkeKuKem(SecureRandom randomness, int identitySize) {
		hibeAlgorithm = new Hibe(identitySize);
		this.identitySize = identitySize;
		this.randomness = randomness;
	}

	/**
	 * Generates a kuKem key pair. Uses {1}^32 as initial identity.
	 */
	@Override
	public KuKemKeyPair gen(SecureRandom randomness) {
		byte[] initialIdentity = new byte[identitySize];
		for (int i = 0; i < identitySize; i++) {
			initialIdentity[i] = 1;
		}
		HibeKeyPair hibeKeyPair = hibeAlgorithm.setup(initialIdentity, randomness);
		return new BrkeKuKemKeyPair(new BrkeKuKemSecretKey(hibeKeyPair.getHibeSecretKey(), initialIdentity, 1),
				new BrkeKuKemPublicKey(hibeKeyPair.getHibePublicParameter(), initialIdentity, 1));
	}

	/**
	 * Generates a kuKem key pair. Uses {1}^32 as initial identity.
	 */
	@Override
	public KuKemKeyPair gen(KeySeed seed) {
		SecureRandom randomness = new SecureRandom(seed.getSeedAsBytes());
		byte[] initialIdentity = new byte[identitySize];
		for (int i = 0; i < identitySize; i++) {
			initialIdentity[i] = 1;
		}
		HibeKeyPair hibeKeyPair = hibeAlgorithm.setup(initialIdentity, randomness);
		return new BrkeKuKemKeyPair(new BrkeKuKemSecretKey(hibeKeyPair.getHibeSecretKey(), initialIdentity, 1),
				new BrkeKuKemPublicKey(hibeKeyPair.getHibePublicParameter(), initialIdentity, 1));
	}

	/**
	 * This function is not used by our version of the brke construction, since
	 * we directly use a seed to generate a (sk,pk)-pair.
	 */
	@Override
	public KuKemPublicKey gen(KuKemSecretKey secretKey) {
		// TODO Auto-generated method stub
		return null;
	}

	/**
	 * Updates a kuKem public Key using associated Data. Currently uses a temporary
	 * class to represent associated data, because some implementations are missing.
	 */
	@Override
	public KuKemPublicKey updatePublicKey(KuKemPublicKey publicKey, KuKemAssociatedData associatedData) {
		BrkeKuKemAssociatedData ad = (BrkeKuKemAssociatedData) associatedData;
		BrkeKuKemPublicKey updatedKey = new BrkeKuKemPublicKey(
				((BrkeKuKemPublicKey) publicKey).getHibePublicParameter(),
				((BrkeKuKemPublicKey) publicKey).getIdentityInformation(), ((BrkeKuKemPublicKey) publicKey).getLevel());
		updatedKey.appendIdentityInformation(ad.getAssociatedData());
		return updatedKey;
	}

	/**
	 * Updates a kuKem secret Key using associated Data. Currently uses a temporary
	 * class to represent associated data, because some implementations are missing.
	 */
	@Override
	public KuKemSecretKey updateSecretKey(KuKemSecretKey secretKey, KuKemAssociatedData associatedData) {
		BrkeKuKemAssociatedData ad = (BrkeKuKemAssociatedData) associatedData;
		BrkeKuKemSecretKey brkeSecretKey = (BrkeKuKemSecretKey) secretKey;
		byte[] identity = brkeSecretKey.getIdentityInformation();
		byte[] newIdentity = new byte[identity.length + ad.getAssociatedData().length];
		System.arraycopy(identity, 0, newIdentity, 0, identity.length);
		System.arraycopy(ad.getAssociatedData(), 0, newIdentity, identity.length, ad.getAssociatedData().length);
		HibeSecretKey newSecretKey = hibeAlgorithm.delegate(brkeSecretKey.getHibeSecretKey(), newIdentity,
				brkeSecretKey.getLevel() + 1, randomness);
		return new BrkeKuKemSecretKey(newSecretKey, newIdentity, brkeSecretKey.getLevel() + 1);
	}

	/**
	 * Generates and encapsulates a symmetric key under the public key.
	 */
	@Override
	public KuKemOutput encapsulate(KuKemPublicKey publicKey) {
		BrkeKuKemPublicKey brkePublicKey = (BrkeKuKemPublicKey) publicKey;
		HibeOutput hibeOutput = hibeAlgorithm.encapsulate(brkePublicKey.getHibePublicParameter(),
				brkePublicKey.getIdentityInformation(), brkePublicKey.getLevel(), randomness);
		return new BrkeKuKemOutput(hibeOutput.getGeneratedKey(), new BrkeKuKemCiphertext(hibeOutput.getCiphertext()));
	}

	/**
	 * Decapsulates a kuKem Ciphertext using the kuKem Secret Key.
	 */
	@Override
	public SymmetricKey decapsulate(KuKemSecretKey secretKey, KuKemCiphertext ciphertext) {
		BrkeKuKemSecretKey brkeSecretKey = (BrkeKuKemSecretKey) secretKey;
		BrkeKuKemCiphertext brkeCiphertext = (BrkeKuKemCiphertext) ciphertext;
		byte[] generatedKey = hibeAlgorithm.decapsulate(brkeSecretKey.getHibeSecretKey(),
				brkeCiphertext.getCiphertext(), brkeSecretKey.getIdentityInformation(), brkeSecretKey.getLevel());
		if (generatedKey == null) {
			return null;
		}
		return new BrkeSymmetricKey(generatedKey);
	}

}
