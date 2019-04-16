package de.rub.rke.test.fakealgorithmset.mocksignature;

import de.rub.rke.signature.SignatureSigningKey;

/**
 * Implementation of SignatureSecretKey for the mock Signature
 * 
 * @author Marco Smeets
 *
 */
public class MockSignatureSigningKey implements SignatureSigningKey {

	int id;

	public MockSignatureSigningKey(int id) {
		this.id = id;
	}

	public int getId() {
		return id;
	}
}
