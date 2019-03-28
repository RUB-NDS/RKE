package de.rub.rkeinstantiation.brkekem;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

import de.rub.rke.kem.KemPublicKey;

/**
 * Class that holds the public key of an ECIES Kem
 * 
 * @author Marco Smeets
 *
 */
public class ECIESKemPublicKey implements KemPublicKey {

	ECPublicKeyParameters publicKey;

	public ECIESKemPublicKey(AsymmetricKeyParameter publicKey) {
		this.publicKey = (ECPublicKeyParameters) publicKey;
	}

	public ECPublicKeyParameters getECPublicParameter() {
		return publicKey;
	}
}
