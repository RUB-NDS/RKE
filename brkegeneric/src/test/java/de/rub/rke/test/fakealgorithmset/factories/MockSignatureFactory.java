package de.rub.rke.test.fakealgorithmset.factories;

import de.rub.rke.factories.SignatureFactory;
import de.rub.rke.signature.SignatureManager;
import de.rub.rke.test.fakealgorithmset.mocksignature.MockSignatureManager;

/**
 * Implementation of SignatureFactory that returns a mock Signature
 * 
 * @author Marco Smeets
 *
 */
public class MockSignatureFactory implements SignatureFactory {

	@Override
	public SignatureManager createSignatureManager() {
		return new MockSignatureManager();
	}

}
