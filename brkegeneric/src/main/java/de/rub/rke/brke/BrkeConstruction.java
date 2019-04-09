package de.rub.rke.brke;

import java.security.SecureRandom;

import de.rub.rke.kukem.KuKemPublicKey;
import de.rub.rke.queuedkukem.QueuedKuKem;
import de.rub.rke.queuedkukem.QueuedKuKemOutput;
import de.rub.rke.randomoracle.KeyedRandomOracle;
import de.rub.rke.randomoracle.KeyedRandomOracleOutput;
import de.rub.rke.signature.SignatureAlgorithm;
import de.rub.rke.signature.SignatureVerificationKey;
import de.rub.rke.variables.AssociatedData;
import de.rub.rke.variables.SymmetricKey;
import de.rub.rke.variables.Transcript;

/**
 * Class for the BRKE construction
 * 
 * @author Marco Smeets
 *
 */
public class BrkeConstruction {

	private SignatureAlgorithm signatureAlgorithm;
	private KeyedRandomOracle randomOracleAlgorithm;
	private QueuedKuKem queuedKuKemAlgorithm;
	private int numberOfUnsynchronizedSentMesssages;
	private int numberOfUnsynchronizedReceivedMessages;
	private Transcript receivingTranscript;
	private Transcript sendingTranscript;
	private boolean initiator;

	/**
	 * Initializes the state of Brke.
	 * 
	 * 
	 * @param randomness   - Randomness used for scheme initialization
	 * @param algorithmSet - set of algorithms
	 * @param initiator    - true (if initiator of conversation; false otherwise)
	 */
	public BrkeConstruction(SecureRandom randomness, BrkeAlgorithmSet algorithmSet, boolean initiator) {
		signatureAlgorithm = algorithmSet.getSignatureFactory().createSignatureAlgorithm();
		randomOracleAlgorithm = algorithmSet.getKeyedRandomOracleFactory().createKeyedRandomOracleAlgorithm();
		queuedKuKemAlgorithm = new QueuedKuKem(algorithmSet.getKuKemFactory().createKuKemAlgorithm(),
				algorithmSet.getKemFactory().createKem(), algorithmSet.getAssociatedDataFactory());
		receivingTranscript = algorithmSet.getTranscriptFactory().createTranscript();
		sendingTranscript = algorithmSet.getTranscriptFactory().createTranscript();
		signatureAlgorithm.init(randomness, initiator);
		randomOracleAlgorithm.init(randomness, initiator);
		queuedKuKemAlgorithm.init(randomness, initiator);
		numberOfUnsynchronizedSentMesssages = 0;
		numberOfUnsynchronizedReceivedMessages = 0;
		this.initiator = initiator;
	}

	/**
	 * Perform the send algorithm of the Brke construction.
	 * @param randomness - randomness used for key generation
	 * @param ad         - associatedData
	 * 
	 * @return BrkeSendOutput containing session key and Brke ciphertext
	 */
	public BrkeSendOutput send(SecureRandom randomness, AssociatedData ad) {
		KuKemPublicKey kuKemPublicKey = queuedKuKemAlgorithm.gen(randomness);
		SignatureVerificationKey signatureVerificationKey = signatureAlgorithm.gen(randomness);

		int numberOfUsedKeysForEncapsulation = queuedKuKemAlgorithm.getNumberOfSavedPublicKeys();

		QueuedKuKemOutput kuKemOutput = queuedKuKemAlgorithm.encapsulate();

		BrkeCiphertext ciphertext = new BrkeCiphertext(numberOfUnsynchronizedReceivedMessages, kuKemPublicKey,
				signatureVerificationKey, numberOfUsedKeysForEncapsulation, kuKemOutput.getCiphertext());

		ciphertext.computeSignature(signatureAlgorithm, ad);

		receivingTranscript.addToTranscriptQueue(initiator, ad, ciphertext);

		sendingTranscript.updateTranscript(initiator, ad, ciphertext);

		KeyedRandomOracleOutput randomOracleOutput = randomOracleAlgorithm
				.querySendRandomOracle(kuKemOutput.getGeneratedKey(), sendingTranscript);

		queuedKuKemAlgorithm.addMatchingPublicKey(randomOracleOutput.getSecretKeySeed());

		queuedKuKemAlgorithm.addToPublicKeyUpdateInformationQueue(ad, ciphertext);

		numberOfUnsynchronizedSentMesssages++;
		numberOfUnsynchronizedReceivedMessages = 0;

		return new BrkeSendOutput(randomOracleOutput.getSessionKey(), ciphertext);
	}

	/**
	 * Perform the receive algorithm of the Brke construction
	 * 
	 * @param ad
	 * @param ciphertext
	 * @return session key
	 */
	public SymmetricKey receive(AssociatedData ad, BrkeCiphertext ciphertext) {

		sendingTranscript.updateTranscript(!initiator, ad, ciphertext);

		if (!signatureAlgorithm.verify(ad, ciphertext)) {
			return null;
		}

		int communicationPartnerReceivedMessages = ciphertext.getNumberOfReceivedMessages();

		KuKemPublicKey ciphertextKuKemPublicKey = ciphertext.getPublicKey();

		SignatureVerificationKey ciphertextSignatureVerificationKey = ciphertext.getVerificationKey();

		numberOfUnsynchronizedSentMesssages -= communicationPartnerReceivedMessages;

		if (numberOfUnsynchronizedSentMesssages < 0) {
			return null;
		}

		queuedKuKemAlgorithm.addUpdatedPublicKey(ciphertextKuKemPublicKey, communicationPartnerReceivedMessages,
				numberOfUnsynchronizedSentMesssages);

		signatureAlgorithm.setVerificationKey(ciphertextSignatureVerificationKey);

		receivingTranscript.updateTranscriptfromQueue(ciphertext.getNumberOfUsedKeys());

		SymmetricKey generatedKey = queuedKuKemAlgorithm.decapsulate(ciphertext.getNumberOfUsedKeys(),
				ciphertext.getCiphertext());

		receivingTranscript.updateTranscript(!initiator, ad, ciphertext);

		KeyedRandomOracleOutput randomOracleOutput = randomOracleAlgorithm.queryReceiveRandomOracle(generatedKey,
				receivingTranscript);

		queuedKuKemAlgorithm.updateSecretKeys(randomOracleOutput.getSecretKeySeed(), ad, ciphertext);

		numberOfUnsynchronizedReceivedMessages++;

		return randomOracleOutput.getSessionKey();
	}
}
