package de.rub.rke.test.fakealgorithmset.mocksignature;

import java.util.Arrays;

import de.rub.rke.signature.SignatureOutput;
import de.rub.rke.signature.SignatureSigningKey;
import de.rub.rke.test.fakealgorithmset.mockvariables.MockAssociatedData;
import de.rub.rke.variables.AssociatedData;

/**
 * Implements SignatureOutput for the mock Signature. Saves all inputs that are
 * given to the sign algorithm.
 * 
 * @author Marco Smeets
 *
 */
public class MockSignatureOutput implements SignatureOutput {

	MockSignatureSigningKey signingKey;
	MockAssociatedData ad;
	int[] encodedCiphertext;

	public MockSignatureOutput(SignatureSigningKey signingKey, AssociatedData ad, int[] encodedCiphertext) {
		this.signingKey = (MockSignatureSigningKey) signingKey;
		this.ad = (MockAssociatedData) ad;
		this.encodedCiphertext = Arrays.copyOf(encodedCiphertext, encodedCiphertext.length);
	}

	public SignatureSigningKey getSigningKey() {
		return signingKey;
	}

	public AssociatedData getAd() {
		return ad;
	}

	public int[] getEncodedCiphertext() {
		return encodedCiphertext;
	}

	public int[] getIntEncoding() {
		int[] encoding = new int[2 + encodedCiphertext.length];
		encoding[0] = signingKey.getId();
		encoding[1] = ad.getIntRepresentation();
		for (int i = 2; i < encodedCiphertext.length + 2; i++) {
			encoding[i] = encodedCiphertext[i - 2];
		}
		return encoding;
	}
}
