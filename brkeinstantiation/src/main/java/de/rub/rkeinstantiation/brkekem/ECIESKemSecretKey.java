package de.rub.rkeinstantiation.brkekem;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;

import de.rub.rke.kem.KemSecretKey;

/**
 * Class that holds a Secret Key for an ECIES Kem
 * 
 * @author Marco Smeets
 *
 */
public class ECIESKemSecretKey implements KemSecretKey {

	ECPrivateKeyParameters secretKey;

	public ECIESKemSecretKey(AsymmetricKeyParameter secretKey) {
		this.secretKey = (ECPrivateKeyParameters) secretKey;
	}

	public ECPrivateKeyParameters getECSecretParameter() {
		return secretKey;
	}

}
