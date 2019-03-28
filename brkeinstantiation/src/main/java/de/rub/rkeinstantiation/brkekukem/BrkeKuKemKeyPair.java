package de.rub.rkeinstantiation.brkekukem;

import de.rub.rke.kukem.KuKemKeyPair;
import de.rub.rke.kukem.KuKemPublicKey;
import de.rub.rke.kukem.KuKemSecretKey;

/**
 * Class for the kuKem key Pair.
 * 
 * @author Marco Smeets
 *
 */
public class BrkeKuKemKeyPair implements KuKemKeyPair {

	private BrkeKuKemSecretKey secretKey;
	private BrkeKuKemPublicKey publicKey;

	public BrkeKuKemKeyPair(BrkeKuKemSecretKey secretKey, BrkeKuKemPublicKey publicKey) {
		this.secretKey = secretKey;
		this.publicKey = publicKey;
	}

	@Override
	public KuKemSecretKey getSecretKey() {
		return secretKey;
	}

	@Override
	public KuKemPublicKey getPublicKey() {
		return publicKey;
	}

}
