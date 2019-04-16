package de.rub.rkeinstantiation.brkekem;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

import de.rub.rke.kem.KemKeyPair;
import de.rub.rke.kem.KemPublicKey;
import de.rub.rke.kem.KemSecretKey;

/**
 * Class that holds the key pair for a ECIES Kem
 * 
 * @author Marco Smeets
 *
 */
public class ECIESKemKeyPair implements KemKeyPair {

	private ECIESKemSecretKey secretKey;
	private ECIESKemPublicKey publicKey;

	public ECIESKemKeyPair(AsymmetricCipherKeyPair keyPair) {
		secretKey = new ECIESKemSecretKey(keyPair.getPrivate());
		publicKey = new ECIESKemPublicKey(keyPair.getPublic());
	}

	@Override
	public KemSecretKey getSecretKey() {
		return secretKey;
	}

	@Override
	public KemPublicKey getPublicKey() {
		return publicKey;
	}

}
