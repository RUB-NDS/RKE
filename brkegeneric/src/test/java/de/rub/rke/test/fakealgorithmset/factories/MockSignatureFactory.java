package de.rub.rke.test.fakealgorithmset.factories;

import de.rub.rke.factories.SignatureFactory;
import de.rub.rke.signature.SignatureAlgorithm;
import de.rub.rke.test.fakealgorithmset.mocksignature.MockSignatureAlgorithm;

/**
 * Implementation of SignatureFactory that returns a mock Signature
 * 
 * @author Marco Smeets
 *
 */
public class MockSignatureFactory implements SignatureFactory {

	@Override
	public SignatureAlgorithm createSignatureAlgorithm() {
		return new MockSignatureAlgorithm();
	}

}
