package de.rub.rke.test.fakealgorithmset.mocksignature;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.Queue;

import de.rub.rke.brke.BrkeCiphertext;
import de.rub.rke.kukem.KuKemPublicKey;
import de.rub.rke.queuedkukem.QueuedKuKemCiphertext;
import de.rub.rke.signature.SignatureAlgorithm;
import de.rub.rke.signature.SignatureOutput;
import de.rub.rke.signature.SignatureVerificationKey;
import de.rub.rke.test.Encoder;
import de.rub.rke.test.fakealgorithmset.mockvariables.MockAssociatedData;
import de.rub.rke.variables.AssociatedData;
import de.rub.rke.variables.KeySeed;

/**
 * Implementation of the mock Signature. Uses int to identify keys. Provides no
 * security and is only used for testing. Signing/ Verification only checks for
 * matching inputs.
 * 
 * 
 * @author Marco Smeets
 *
 */
public class MockSignatureAlgorithm implements SignatureAlgorithm {

	/**
	 * Saves signing keys and the verification key for the communication partner
	 */
	Queue<MockSignatureSigningKey> signingKeys;
	MockSignatureVerificationKey communicationPartnerVerificationKey;

	public MockSignatureAlgorithm() {
		signingKeys = new LinkedList<MockSignatureSigningKey>();
	}

	/**
	 * Initializes the signature algorithm
	 */
	@Override
	public void init(SecureRandom randomness, boolean initiator) {
		if (initiator) {
			MockSignatureKeyPair keyPair1 = new MockSignatureKeyPair(randomness.nextInt());
			MockSignatureKeyPair keyPair2 = new MockSignatureKeyPair(randomness.nextInt());
			signingKeys.add((MockSignatureSigningKey) keyPair1.getSigningKey());
			communicationPartnerVerificationKey = (MockSignatureVerificationKey) keyPair2.getVerificationKey();
		} else {
			MockSignatureKeyPair keyPair1 = new MockSignatureKeyPair(randomness.nextInt());
			MockSignatureKeyPair keyPair2 = new MockSignatureKeyPair(randomness.nextInt());
			signingKeys.add((MockSignatureSigningKey) keyPair2.getSigningKey());
			communicationPartnerVerificationKey = (MockSignatureVerificationKey) keyPair1.getVerificationKey();
		}

	}

	/**
	 * Generates a key pair, saves the signing key and outputs the verification key
	 */
	@Override
	public SignatureVerificationKey gen(SecureRandom randomness) {
		MockSignatureKeyPair generatedKeyPair = new MockSignatureKeyPair(randomness.nextInt());
		signingKeys.add((MockSignatureSigningKey) generatedKeyPair.getSigningKey());
		return generatedKeyPair.getVerificationKey();
	}

	/**
	 * Not needed
	 */
	@Override
	public SignatureVerificationKey gen(KeySeed seed) {
		// TODO Auto-generated method stub
		return null;
	}

	/**
	 * Sets the verification key
	 */
	@Override
	public void setVerificationKey(SignatureVerificationKey verificationKey) {
		this.communicationPartnerVerificationKey = (MockSignatureVerificationKey) verificationKey;
	}

	/**
	 * Signs a Brke ciphertext
	 */
	@Override
	public SignatureOutput sign(AssociatedData ad, int numberOfReceivedMessages, KuKemPublicKey publicKey,
			SignatureVerificationKey verificationKey, int epoch, QueuedKuKemCiphertext ciphertext) {
		return new MockSignatureOutput(signingKeys.remove(), ad, Encoder.encodeFakeBrkeCiphertextForSign(
				new BrkeCiphertext(numberOfReceivedMessages, publicKey, verificationKey, epoch, ciphertext)));
	}

	/**
	 * Verifies the signature in a Brke ciphertext
	 */
	@Override
	public boolean verify(AssociatedData ad, BrkeCiphertext ciphertext) {
		MockSignatureOutput signature = (MockSignatureOutput) ciphertext.getSignature();

		MockSignatureSigningKey signerKey = (MockSignatureSigningKey) signature.getSigningKey();

		MockAssociatedData inputAd = (MockAssociatedData) ad;
		MockAssociatedData signatureAd = (MockAssociatedData) signature.getAd();

		int[] inputEncodedCiphertext = Encoder.encodeFakeBrkeCiphertextForSign(ciphertext);
		int[] signatureEncodedCiphertext = signature.getEncodedCiphertext();

		boolean result = false;

		if (communicationPartnerVerificationKey.getId() == signerKey.getId()) {
			if (inputAd.getIntRepresentation() == signatureAd.getIntRepresentation()) {
				if (Arrays.equals(inputEncodedCiphertext, signatureEncodedCiphertext)) {
					result = true;
				}
			}
		}
		return result;
	}

}
