package de.rub.rke.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

import org.junit.jupiter.api.Test;

import de.rub.rke.brke.BrkeCiphertext;
import de.rub.rke.brke.BrkeConstruction;
import de.rub.rke.brke.BrkeSendOutput;
import de.rub.rke.kem.KemKeyPair;
import de.rub.rke.kem.KemOutput;
import de.rub.rke.kukem.KuKemKeyPair;
import de.rub.rke.kukem.KuKemOutput;
import de.rub.rke.queuedkukem.QueuedKuKemCiphertext;
import de.rub.rke.signature.SignatureVerificationKey;
import de.rub.rke.test.fakealgorithmset.factories.MockKemFactory;
import de.rub.rke.test.fakealgorithmset.factories.MockKuKemAssociatedDataFactory;
import de.rub.rke.test.fakealgorithmset.factories.MockKuKemFactory;
import de.rub.rke.test.fakealgorithmset.factories.MockRandomOracleFactory;
import de.rub.rke.test.fakealgorithmset.factories.MockSignatureFactory;
import de.rub.rke.test.fakealgorithmset.factories.MockTranscriptFactory;
import de.rub.rke.test.fakealgorithmset.mockkem.MockKemKeyPair;
import de.rub.rke.test.fakealgorithmset.mockkem.MockKemOutput;
import de.rub.rke.test.fakealgorithmset.mockkem.MockKeyEncapsulationMechanism;
import de.rub.rke.test.fakealgorithmset.mockkukem.MockKeyUpdateableKem;
import de.rub.rke.test.fakealgorithmset.mockkukem.MockKuKemAssociatedData;
import de.rub.rke.test.fakealgorithmset.mockkukem.MockKuKemPublicKey;
import de.rub.rke.test.fakealgorithmset.mockkukem.MockKuKemSecretKey;
import de.rub.rke.test.fakealgorithmset.mockrandomoracle.MockRandomOracle;
import de.rub.rke.test.fakealgorithmset.mockrandomoracle.MockRandomOracleOutput;
import de.rub.rke.test.fakealgorithmset.mocksignature.MockSignatureManager;
import de.rub.rke.test.fakealgorithmset.mockvariables.MockAssociatedData;
import de.rub.rke.test.fakealgorithmset.mockvariables.MockKeySeed;
import de.rub.rke.test.fakealgorithmset.mockvariables.MockSymmetricKey;
import de.rub.rke.variables.SymmetricKey;
import de.rub.rke.variables.Transcript;

public class TestBrke {

	/**
	 * Test the mock kuKem algorithm.
	 */
	@Test
	public void testMockKuKem() {
		MockKuKemFactory kukemFactory = new MockKuKemFactory();
		MockKeyUpdateableKem kuKem = (MockKeyUpdateableKem) kukemFactory.createKuKemAlgorithm();
		SecureRandom randomness = new SecureRandom();

		KuKemKeyPair kuKemKeyPair1 = kuKem.gen(randomness);
		KuKemKeyPair kuKemKeyPair2 = kuKem.gen(randomness);

		KuKemOutput kuKemOutput = kuKem.encapsulate(kuKemKeyPair1.getPublicKey());
		/**
		 * Correct secret key should decrypt ciphertext, decapsulation to wrong secret
		 * key should return null
		 */
		assertEquals(((MockSymmetricKey) kuKemOutput.getKey()).getId(),
				((MockSymmetricKey) kuKem.decapsulate(kuKemKeyPair1.getSecretKey(), kuKemOutput.getCiphertext()))
						.getId());
		assertNull(kuKem.decapsulate(kuKemKeyPair2.getSecretKey(), kuKemOutput.getCiphertext()));

		/**
		 * Test the update functionality of the KuKem
		 */
		MockKuKemPublicKey[] publicKeys = new MockKuKemPublicKey[3];
		MockKuKemSecretKey[] secretKeys = new MockKuKemSecretKey[3];

		publicKeys[0] = (MockKuKemPublicKey) kuKemKeyPair1.getPublicKey();
		secretKeys[0] = (MockKuKemSecretKey) kuKemKeyPair1.getSecretKey();

		/**
		 * Construct simple Brke Ciphertext and Associated Data to test key updates
		 */
		MockSignatureFactory signatureFactory = new MockSignatureFactory();
		MockSignatureManager signatureScheme = (MockSignatureManager) signatureFactory.createSignatureManager();
		signatureScheme.init(randomness, true);
		SignatureVerificationKey signatureVerificationKey = signatureScheme.gen(randomness);

		MockAssociatedData associatedData = new MockAssociatedData(22);
		MockKeyEncapsulationMechanism mockKem = new MockKeyEncapsulationMechanism(randomness);
		KemKeyPair kemKeyPair = mockKem.gen(randomness);
		KemOutput kemOutput = mockKem.encapsulate(kemKeyPair.getPublicKey());
		QueuedKuKemCiphertext queuedKuKemCiphertext = new QueuedKuKemCiphertext(kemOutput.getCiphertext(), 1, null);
		BrkeCiphertext testCiphertext = new BrkeCiphertext(1, kuKemKeyPair1.getPublicKey(), signatureVerificationKey, 0,
				queuedKuKemCiphertext);

		testCiphertext.computeSignature(signatureScheme, associatedData);

		MockKuKemAssociatedData updateInformation = new MockKuKemAssociatedData(associatedData, testCiphertext);

		/**
		 * Update public key
		 */

		publicKeys[1] = (MockKuKemPublicKey) kuKem.updatePublicKey(publicKeys[0], updateInformation);
		publicKeys[2] = (MockKuKemPublicKey) kuKem.updatePublicKey(publicKeys[1], updateInformation);

		/**
		 * Update Secret Key
		 */

		secretKeys[1] = (MockKuKemSecretKey) kuKem.updateSecretKey(secretKeys[0], updateInformation);
		secretKeys[2] = (MockKuKemSecretKey) kuKem.updateSecretKey(secretKeys[1], updateInformation);

		KuKemOutput outputLevel0 = kuKem.encapsulate(publicKeys[0]);
		KuKemOutput outputLevel1 = kuKem.encapsulate(publicKeys[1]);
		KuKemOutput outputLevel2 = kuKem.encapsulate(publicKeys[2]);

		/**
		 * Only the secret key of the sepecific depth should be able to decrypt a key
		 */
		assertEquals(((MockSymmetricKey) outputLevel0.getKey()).getId(),
				((MockSymmetricKey) kuKem.decapsulate(secretKeys[0], outputLevel0.getCiphertext())).getId());
		assertEquals(((MockSymmetricKey) outputLevel1.getKey()).getId(),
				((MockSymmetricKey) kuKem.decapsulate(secretKeys[1], outputLevel1.getCiphertext())).getId());
		assertEquals(((MockSymmetricKey) outputLevel2.getKey()).getId(),
				((MockSymmetricKey) kuKem.decapsulate(secretKeys[2], outputLevel2.getCiphertext())).getId());
		assertNull(kuKem.decapsulate(secretKeys[0], outputLevel1.getCiphertext()));
		assertNull(kuKem.decapsulate(secretKeys[0], outputLevel2.getCiphertext()));
		assertNull(kuKem.decapsulate(secretKeys[1], outputLevel0.getCiphertext()));
		assertNull(kuKem.decapsulate(secretKeys[1], outputLevel2.getCiphertext()));
		assertNull(kuKem.decapsulate(secretKeys[2], outputLevel0.getCiphertext()));
		assertNull(kuKem.decapsulate(secretKeys[2], outputLevel1.getCiphertext()));
	}

	/**
	 * Test the mock Kem
	 */
	@Test
	public void testMockKem() {
		SecureRandom randomness = null;
		try {
			randomness = SecureRandom.getInstance("SHA1PRNG");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		byte[] randomnessSeed = { 1, 2, 3, 4, 5 };
		randomness.setSeed(randomnessSeed);
		MockKeyEncapsulationMechanism mockKem = new MockKeyEncapsulationMechanism(randomness);
		MockKemKeyPair kemKeyPair1 = (MockKemKeyPair) mockKem.gen(randomness);
		MockKemKeyPair kemKeyPair2 = (MockKemKeyPair) mockKem.gen(randomness);

		MockKemOutput kemOutput1 = (MockKemOutput) mockKem.encapsulate(kemKeyPair1.getPublicKey());
		/**
		 * Decapsulating to correct secret Key should return the symmetric key,
		 * decapsulating to wrong secret key should return null
		 */
		assertEquals(((MockSymmetricKey) kemOutput1.getKey()).getId(),
				((MockSymmetricKey) mockKem.decapsulate(kemKeyPair1.getSecretKey(), kemOutput1.getCiphertext()))
						.getId());
		assertNull(mockKem.decapsulate(kemKeyPair2.getSecretKey(), kemOutput1.getCiphertext()));
	}

	/**
	 * Test the mock Signature algorithm.
	 */
	@Test
	public void testMockSignature() {
		SecureRandom randomnessA = null;
		SecureRandom randomnessB = null;
		try {
			randomnessA = SecureRandom.getInstance("SHA1PRNG");
			randomnessB = SecureRandom.getInstance("SHA1PRNG");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		MockKuKemFactory kukemFactory = new MockKuKemFactory();
		MockSignatureFactory signatureFactory = new MockSignatureFactory();
		byte[] randomnessSeed = { 1, 2, 3, 4, 5 };
		randomnessA.setSeed(randomnessSeed);
		randomnessB.setSeed(randomnessSeed);

		MockSignatureManager signatureSchemeA = (MockSignatureManager) signatureFactory.createSignatureManager();
		MockSignatureManager signatureSchemeB = (MockSignatureManager) signatureFactory.createSignatureManager();
		MockKeyUpdateableKem kuKem = (MockKeyUpdateableKem) kukemFactory.createKuKemAlgorithm();

		signatureSchemeA.init(randomnessA, true);
		signatureSchemeB.init(randomnessB, false);

		/**
		 * Construct a Brke ciphertext
		 */
		KuKemKeyPair kuKemKeyPair = kuKem.gen(randomnessA);
		MockAssociatedData associatedData = new MockAssociatedData(22);
		MockKeyEncapsulationMechanism mockKem = new MockKeyEncapsulationMechanism(randomnessA);
		KemKeyPair kemKeyPair = mockKem.gen(randomnessA);
		KemOutput kemOutput = mockKem.encapsulate(kemKeyPair.getPublicKey());
		QueuedKuKemCiphertext queuedKuKemCiphertext = new QueuedKuKemCiphertext(kemOutput.getCiphertext(), 1, null);

		SignatureVerificationKey verificationKeyA = signatureSchemeA.gen(randomnessA);
		SignatureVerificationKey verificationKeyB = signatureSchemeB.gen(randomnessB);

		/**
		 * Create ciphertext for A
		 */
		BrkeCiphertext testCiphertextA = new BrkeCiphertext(1, kuKemKeyPair.getPublicKey(), verificationKeyA, 0,
				queuedKuKemCiphertext);
		testCiphertextA.computeSignature(signatureSchemeA, associatedData);

		/**
		 * Create ciphertext for B
		 */
		BrkeCiphertext testCiphertextB = new BrkeCiphertext(1, kuKemKeyPair.getPublicKey(), verificationKeyB, 0,
				queuedKuKemCiphertext);
		testCiphertextB.computeSignature(signatureSchemeB, associatedData);

		/**
		 * Verification with correct secret key should return true; Verification with
		 * false secret key should return false
		 */
		assertTrue(signatureSchemeA.verify(associatedData, testCiphertextB));
		assertTrue(signatureSchemeB.verify(associatedData, testCiphertextA));
		assertFalse(signatureSchemeA.verify(associatedData, testCiphertextA));
		assertFalse(signatureSchemeB.verify(associatedData, testCiphertextB));
	}

	/**
	 * Tests the mock random oracle algorithm
	 */
	@Test
	public void testFakeRandomOracle() {
		MockKuKemFactory kukemFactory = new MockKuKemFactory();
		MockSignatureFactory signatureFactory = new MockSignatureFactory();
		MockRandomOracleFactory randomOracleFactory = new MockRandomOracleFactory();

		MockSignatureManager signatureScheme = (MockSignatureManager) signatureFactory.createSignatureManager();
		MockKeyUpdateableKem kuKem = (MockKeyUpdateableKem) kukemFactory.createKuKemAlgorithm();

		SecureRandom randomness = new SecureRandom();

		signatureScheme.init(randomness, true);
		KuKemKeyPair kuKemKeyPair = kuKem.gen(randomness);

		SignatureVerificationKey signatureVerificationKey = signatureScheme.gen(randomness);

		/**
		 * Create a BrkeCiphertext and a simple Transcript.
		 */
		MockAssociatedData associatedData = new MockAssociatedData(22);
		KuKemOutput kuKemOutput = kuKem.encapsulate(kuKemKeyPair.getPublicKey());
		MockKeyEncapsulationMechanism mockKem = new MockKeyEncapsulationMechanism(randomness);
		KemKeyPair kemKeyPair = mockKem.gen(randomness);
		KemOutput kemOutput = mockKem.encapsulate(kemKeyPair.getPublicKey());
		QueuedKuKemCiphertext queuedKuKemCiphertext = new QueuedKuKemCiphertext(kemOutput.getCiphertext(), 1, null);
		BrkeCiphertext testCiphertext = new BrkeCiphertext(1, kuKemKeyPair.getPublicKey(), signatureVerificationKey, 0,
				queuedKuKemCiphertext);

		testCiphertext.computeSignature(signatureScheme, associatedData);

		MockTranscriptFactory transcriptFactory = new MockTranscriptFactory();
		Transcript testTranscript = transcriptFactory.createTranscript();
		testTranscript.updateTranscript(true, associatedData, testCiphertext);

		byte[] randomnessSeed = { 1, 2, 3, 4, 5 };
		SecureRandom randomnessA = null;
		SecureRandom randomnessB = null;
		try {
			randomnessA = SecureRandom.getInstance("SHA1PRNG");
			randomnessB = SecureRandom.getInstance("SHA1PRNG");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		randomnessA.setSeed(randomnessSeed);
		randomnessB.setSeed(randomnessSeed);

		MockRandomOracle randomOracleA = (MockRandomOracle) randomOracleFactory.createKeyedRandomOracleAlgorithm();
		MockRandomOracle randomOracleB = (MockRandomOracle) randomOracleFactory.createKeyedRandomOracleAlgorithm();

		randomOracleA.init(randomnessA, true);
		randomOracleB.init(randomnessB, false);

		/**
		 * Verifiy that the random Oracle output is the same for two seperate calls with
		 * the same input
		 */
		MockRandomOracleOutput randomOracleOutputA = (MockRandomOracleOutput) randomOracleA
				.querySendRandomOracle(kuKemOutput.getKey(), testTranscript);
		MockRandomOracleOutput randomOracleOutputB = (MockRandomOracleOutput) randomOracleB
				.queryReceiveRandomOracle(kuKemOutput.getKey(), testTranscript);
		assertEquals(((MockSymmetricKey) randomOracleOutputA.getSessionKey()).getId(),
				((MockSymmetricKey) randomOracleOutputB.getSessionKey()).getId());
		assertEquals(((MockKeySeed) randomOracleOutputA.getSecretKeySeed()).getSeed(),
				((MockKeySeed) randomOracleOutputB.getSecretKeySeed()).getSeed());

		/**
		 * Verifiy that the random Oracle output is not the same for two seperate calls
		 * with different input
		 */
		MockRandomOracleOutput randomOracleOutputB2 = (MockRandomOracleOutput) randomOracleB
				.querySendRandomOracle(kuKemOutput.getKey(), testTranscript);
		assertNotEquals(((MockSymmetricKey) randomOracleOutputA.getSessionKey()).getId(),
				((MockSymmetricKey) randomOracleOutputB2.getSessionKey()).getId());
		assertNotEquals(((MockKeySeed) randomOracleOutputA.getSecretKeySeed()).getSeed(),
				((MockKeySeed) randomOracleOutputB2.getSecretKeySeed()).getSeed());
	}

	/**
	 * Test the Brke construction with the mock algorithms
	 */
	@Test
	public void testBrke() {
		MockKuKemFactory kukemFactory = new MockKuKemFactory();
		MockSignatureFactory signatureFactory = new MockSignatureFactory();
		MockRandomOracleFactory randomOracleFactory = new MockRandomOracleFactory();
		MockTranscriptFactory transcriptFactory = new MockTranscriptFactory();
		MockKemFactory kemFactory = new MockKemFactory();
		MockKuKemAssociatedDataFactory associatedDataFactory = new MockKuKemAssociatedDataFactory();
		MockBrkeAlgorithmSet brkeAlgorithmSet = new MockBrkeAlgorithmSet(kukemFactory, kemFactory, randomOracleFactory,
				associatedDataFactory, signatureFactory, transcriptFactory);

		/**
		 * Initialize A and B with the same randomness.
		 */
		byte[] randomnessSeedForInit = { 1, 2, 3, 4, 5 };
		SecureRandom randomnessA = null;
		SecureRandom randomnessB = null;
		try {
			randomnessA = SecureRandom.getInstance("SHA1PRNG");
			randomnessB = SecureRandom.getInstance("SHA1PRNG");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		randomnessA.setSeed(randomnessSeedForInit);
		randomnessB.setSeed(randomnessSeedForInit);

		BrkeConstruction brkeUserA = new BrkeConstruction(randomnessA, brkeAlgorithmSet, true);
		BrkeConstruction brkeUserB = new BrkeConstruction(randomnessB, brkeAlgorithmSet, false);

		/**
		 * Seed randomness used for key generation in the send Algorithm
		 */
		byte[] randomnessSeedForSendA = { 2, 45, 62, 3 };
		byte[] randomnessSeedForSendB = { 3, 93, 23, 1 };
		MockAssociatedData associatedData = new MockAssociatedData(22);
		SecureRandom randomnessSendA = null;
		SecureRandom randomnessSendB = null;
		try {
			randomnessSendA = SecureRandom.getInstance("SHA1PRNG");
			randomnessSendB = SecureRandom.getInstance("SHA1PRNG");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		randomnessSendA.setSeed(randomnessSeedForSendA);
		randomnessSendB.setSeed(randomnessSeedForSendB);

		/**
		 * Prepare arrays to test the Brke construction
		 */
		BrkeSendOutput[] sendOutputA = new BrkeSendOutput[20];
		SymmetricKey[] receiveOutputA = new SymmetricKey[20];
		int lastReceivedMessageA = -1;

		BrkeSendOutput[] sendOutputB = new BrkeSendOutput[20];
		SymmetricKey[] receiveOutputB = new SymmetricKey[20];
		int lastReceivedMessageB = -1;

		/**
		 * Seed randomness used to simulate asynchronous communication
		 */
		long seed = 1785324;
		Random rng = new Random(seed);

		/**
		 * Each user sends 20 messages, but it is randomized at which point the other
		 * user receives the next 'set' of messages. This way we can simulate
		 * asynchronous communication and see that the Brke construction achieves its
		 * purpose.
		 */
		for (int i = 0; i < 20; i++) {
			sendOutputA[i] = brkeUserA.send(randomnessSendA, associatedData);
			if (rng.nextBoolean()) {
				for (int j = lastReceivedMessageB + 1; j <= i; j++) {
					receiveOutputB[j] = brkeUserB.receive(associatedData, sendOutputA[j].getCiphertext());
				}
				lastReceivedMessageB = i;
			}
			sendOutputB[i] = brkeUserB.send(randomnessSendB, associatedData);
			if (rng.nextBoolean()) {
				for (int j = lastReceivedMessageA + 1; j <= i; j++) {
					receiveOutputA[j] = brkeUserA.receive(associatedData, sendOutputB[j].getCiphertext());
				}
				lastReceivedMessageA = i;
			}
		}

		/**
		 * After 20 messages have been sent, we let A and B receive the remaining
		 * messages
		 */

		if (lastReceivedMessageA != 19) {
			for (int j = lastReceivedMessageA + 1; j <= 19; j++) {
				receiveOutputA[j] = brkeUserA.receive(associatedData, sendOutputB[j].getCiphertext());
			}
		}
		if (lastReceivedMessageB != 19) {
			for (int j = lastReceivedMessageB + 1; j <= 19; j++) {
				receiveOutputB[j] = brkeUserB.receive(associatedData, sendOutputA[j].getCiphertext());
			}
		}
		/**
		 * Check if all 40 (20 for each direction) established session keys are the
		 * same.
		 */
		for (int i = 0; i < 20; i++) {
			assertEquals(((MockSymmetricKey) sendOutputA[i].getSessionKey()).getId(),
					((MockSymmetricKey) receiveOutputB[i]).getId());
			assertEquals(((MockSymmetricKey) sendOutputB[i].getSessionKey()).getId(),
					((MockSymmetricKey) receiveOutputA[i]).getId());
		}
		/**
		 * Test that a user cannot receive a message with a 'wrong' state.
		 */
		for (int i = 0; i < 20; i++) {
			if (rng.nextBoolean()) {
				assertNull(brkeUserA.receive(associatedData, sendOutputB[i].getCiphertext()));
			} else {
				assertNull(brkeUserB.receive(associatedData, sendOutputA[i].getCiphertext()));
			}
		}
	}

}
