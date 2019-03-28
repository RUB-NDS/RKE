package de.rub.rke.test.fakealgorithmset.mocksignature;

import de.rub.rke.signature.SignatureKeyPair;
import de.rub.rke.signature.SignatureVerificationKey;
import de.rub.rke.signature.SignatureSigningKey;

/**
 * Implements SignatureKeyPair for the mock Signature
 * 
 * @author Marco Smeets
 *
 */
public class MockSignatureKeyPair implements SignatureKeyPair {

	SignatureSigningKey signingKey;
	SignatureVerificationKey verificationKey;

	public MockSignatureKeyPair(int id) {
		signingKey = new MockSignatureSigningKey(id);
		verificationKey = new MockSignatureVerificationKey(id);
	}

	@Override
	public SignatureSigningKey getSigningKey() {
		// TODO Auto-generated method stub
		return signingKey;
	}

	@Override
	public SignatureVerificationKey getVerificationKey() {
		// TODO Auto-generated method stub
		return verificationKey;
	}

}
