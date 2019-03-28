package de.rub.rke.test.fakealgorithmset.mocksignature;

import de.rub.rke.signature.SignatureVerificationKey;

/**
 * Implementation of SignaturePublicKey for the mock Signature
 * 
 * @author Marco Smeets
 *
 */
public class MockSignatureVerificationKey implements SignatureVerificationKey {

	int id;

	public MockSignatureVerificationKey(int id) {
		this.id = id;
	}

	public int getId() {
		return id;
	}
}
