package de.rub.rkeinstantiation;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.junit.jupiter.api.Test;

import de.rub.rke.brke.BrkeCiphertext;
import de.rub.rke.brke.BrkeConstruction;
import de.rub.rke.brke.BrkeSendOutput;
import de.rub.rke.kukem.KuKemKeyPair;
import de.rub.rke.kukem.KuKemOutput;
import de.rub.rke.queuedkukem.QueuedKuKemCiphertext;
import de.rub.rke.variables.SymmetricKey;
import de.rub.rkeinstantiation.algorithmset.AlgorithmSet1;
import de.rub.rkeinstantiation.brkekem.ECIESKemCiphertext;
import de.rub.rkeinstantiation.brkekem.ECIESKemKeyPair;
import de.rub.rkeinstantiation.brkekem.ECIESKemOutput;
import de.rub.rkeinstantiation.brkekem.ECIESKeyEncapsulationMechanism;
import de.rub.rkeinstantiation.brkekukem.BrkeKuKem;
import de.rub.rkeinstantiation.brkekukem.BrkeKuKemAssociatedData;
import de.rub.rkeinstantiation.brkekukem.BrkeKuKemOutput;
import de.rub.rkeinstantiation.brkekukem.BrkeKuKemPublicKey;
import de.rub.rkeinstantiation.brkekukem.BrkeKuKemSecretKey;
import de.rub.rkeinstantiation.brkerandomoracle.HKDFRandomOracle;
import de.rub.rkeinstantiation.brkerandomoracle.HKDFRandomOracleOutput;
import de.rub.rkeinstantiation.brkesignature.DLPChameleonOTSignatureAlgorithm;
import de.rub.rkeinstantiation.brkesignature.DLPChameleonVerificationKey;
import de.rub.rkeinstantiation.factories.BrkeKuKemAssociatedDataFactory;
import de.rub.rkeinstantiation.factories.BrkeKuKemFactory;
import de.rub.rkeinstantiation.factories.BrkeTranscriptFactory;
import de.rub.rkeinstantiation.factories.DLPChameleonSignatureFactory;
import de.rub.rkeinstantiation.factories.ECIESKemFactory;
import de.rub.rkeinstantiation.factories.HKDFRandomOracleFactory;
import de.rub.rkeinstantiation.hibewrapper.HibePublicParameter;
import de.rub.rkeinstantiation.utility.SecureRandomBuilder;
import de.rub.rkeinstantiation.variables.BrkeAssociatedData;
import de.rub.rkeinstantiation.variables.BrkeSymmetricKey;
import de.rub.rkeinstantiation.variables.BrkeTranscript;

/**
 * Test class for the Brke Instantiation and algorithm implementations.
 * 
 * @author Marco Smeets
 *
 */
public class TestBrkeInstantiation {

	/**
	 * Tests the DLP-Based Signature Algorithm.
	 */
	@Test
	void testDLPChameleonOTSignature() {
		byte[] seed = { 1, 2, 3, 4, 5, 6, 7, 8, 9 };
		SecureRandom randomness = SecureRandomBuilder.createSeedableRandomness();
		SecureRandom randomnessA = SecureRandomBuilder.createSeedableRandomness();
		SecureRandom randomnessB = SecureRandomBuilder.createSeedableRandomness();
		randomness.setSeed(seed);
		randomnessA.setSeed(seed);
		randomnessB.setSeed(seed);
		DLPChameleonSignatureFactory signatureFactory = new DLPChameleonSignatureFactory();

		DLPChameleonOTSignatureAlgorithm signatureAlgorithmA = (DLPChameleonOTSignatureAlgorithm) signatureFactory
				.createSignatureAlgorithm();
		DLPChameleonOTSignatureAlgorithm signatureAlgorithmB = (DLPChameleonOTSignatureAlgorithm) signatureFactory
				.createSignatureAlgorithm();

		signatureAlgorithmA.init(randomnessA, true);
		signatureAlgorithmB.init(randomnessB, false);

		BrkeCiphertext ciphertextA = createTestCiphertextForSigning(randomness);
		BrkeCiphertext ciphertextB = createTestCiphertextForSigning(randomness);
		byte[] adInput = { 1, 2, 3, 4, 5 };
		BrkeAssociatedData associatedData = new BrkeAssociatedData(adInput);

		ciphertextA.computeSignature(signatureAlgorithmA, associatedData);
		ciphertextB.computeSignature(signatureAlgorithmB, associatedData);

		/**
		 * Signatures should be only valid if used with the corresponding keys, thus,
		 * only for the correct users.
		 */
		assertTrue(signatureAlgorithmA.verify(associatedData, ciphertextB));
		assertTrue(signatureAlgorithmB.verify(associatedData, ciphertextA));

		assertFalse(signatureAlgorithmA.verify(associatedData, ciphertextA));
		assertFalse(signatureAlgorithmB.verify(associatedData, ciphertextB));
	}

	/**
	 * Tests the HKDF-Based RandomOracle.
	 */
	@Test
	void testHKDFRandomOracle() {
		byte[] seed = { 1, 2, 3, 4, 5, 6, 7, 8, 9 };
		SecureRandom randomness = SecureRandomBuilder.createSeedableRandomness();
		SecureRandom randomnessA = SecureRandomBuilder.createSeedableRandomness();
		SecureRandom randomnessB = SecureRandomBuilder.createSeedableRandomness();
		randomness.setSeed(seed);
		randomnessA.setSeed(seed);
		randomnessB.setSeed(seed);

		HKDFRandomOracleFactory randomOracleFactory = new HKDFRandomOracleFactory();
		HKDFRandomOracle randomOracleFunctionA = (HKDFRandomOracle) randomOracleFactory
				.createKeyedRandomOracleAlgorithm();
		HKDFRandomOracle randomOracleFunctionB = (HKDFRandomOracle) randomOracleFactory
				.createKeyedRandomOracleAlgorithm();

		randomOracleFunctionA.init(randomnessA, true);
		randomOracleFunctionB.init(randomnessB, false);

		byte[] adInput = { 1, 2, 3, 4, 5 };
		BrkeAssociatedData associatedData = new BrkeAssociatedData(adInput);
		BrkeCiphertext ciphertext = createTestCiphertext(randomness, associatedData);

		BrkeTranscriptFactory transcriptFactory = new BrkeTranscriptFactory();
		BrkeTranscript transcriptA = (BrkeTranscript) transcriptFactory.createTranscript();
		BrkeTranscript transcriptB = (BrkeTranscript) transcriptFactory.createTranscript();

		transcriptA.updateTranscript(true, associatedData, ciphertext);
		transcriptB.updateTranscript(true, associatedData, ciphertext);
		byte[] keybytes = new byte[16];
		randomness.nextBytes(keybytes);
		BrkeSymmetricKey key = new BrkeSymmetricKey(keybytes);

		HKDFRandomOracleOutput randomOracleOutputA = (HKDFRandomOracleOutput) randomOracleFunctionA
				.querySendRandomOracle(key, transcriptA);
		HKDFRandomOracleOutput randomOracleOutputB = (HKDFRandomOracleOutput) randomOracleFunctionB
				.queryReceiveRandomOracle(key, transcriptB);

		/**
		 * Output for both 'Users' should be equal, if queried with the corresponding
		 * inputs. And if User A used the Send Oracle and user B the Receive Oracle
		 * 
		 */
		assertArrayEquals(((BrkeSymmetricKey) randomOracleOutputA.getSessionKey()).getKeyBytes(),
				((BrkeSymmetricKey) randomOracleOutputB.getSessionKey()).getKeyBytes());
		assertArrayEquals(randomOracleOutputA.getSecretKeySeed().getSeedAsByte(),
				randomOracleOutputB.getSecretKeySeed().getSeedAsByte());
	}

	/**
	 * Tests the BrkeKuKem.
	 */
	@Test
	void testBrkeKuKem() {
		byte[] seed = { 1, 2, 3, 4, 5, 6, 7, 8, 9 };
		SecureRandom randomness = SecureRandomBuilder.createSeedableRandomness();
		randomness.setSeed(seed);

		BrkeKuKemFactory kuKemFactory = new BrkeKuKemFactory();
		BrkeKuKem kuKem = (BrkeKuKem) kuKemFactory.createKuKemAlgorithm();

		KuKemKeyPair keyPair1 = kuKem.gen(randomness);
		KuKemKeyPair keyPair2 = kuKem.gen(randomness);

		KuKemOutput output1 = kuKem.encapsulate(keyPair1.getPublicKey());

		BrkeSymmetricKey key = (BrkeSymmetricKey) kuKem.decapsulate(keyPair1.getSecretKey(), output1.getCiphertext());

		/**
		 * Decapsulating to matching secret key should return the key. Decapsulating to
		 * wrong secret key should return null.
		 */

		assertArrayEquals(key.getKeyBytes(), ((BrkeSymmetricKey) output1.getKey()).getKeyBytes());
		assertNull(kuKem.decapsulate(keyPair2.getSecretKey(), output1.getCiphertext()));

		BrkeKuKemPublicKey[] publicKeys = new BrkeKuKemPublicKey[5];
		BrkeKuKemSecretKey[] secretKeys = new BrkeKuKemSecretKey[5];

		publicKeys[0] = (BrkeKuKemPublicKey) keyPair1.getPublicKey();
		secretKeys[0] = (BrkeKuKemSecretKey) keyPair1.getSecretKey();

		/**
		 * Test the update functionality of the BrkeKuKem
		 */
		byte[] adInput = { 1, 2, 3, 4, 5 };
		BrkeAssociatedData associatedData = new BrkeAssociatedData(adInput);
		BrkeCiphertext ciphertext = createTestCiphertext(randomness, associatedData);
		BrkeKuKemAssociatedDataFactory associatedDataFactory = new BrkeKuKemAssociatedDataFactory();
		BrkeKuKemAssociatedData ad = (BrkeKuKemAssociatedData) associatedDataFactory
				.createAssociatedData(associatedData, ciphertext);

		/**
		 * Update both keys five times.
		 */
		for (int i = 1; i < 5; i++) {
			publicKeys[i] = (BrkeKuKemPublicKey) kuKem.updatePublicKey(publicKeys[i - 1], ad);
			secretKeys[i] = (BrkeKuKemSecretKey) kuKem.updateSecretKey(secretKeys[i - 1], ad);
		}

		BrkeKuKemOutput[] output = new BrkeKuKemOutput[5];

		/**
		 * Encapsulate and Decapsulating with the correct key of the corresponding level
		 * should return the generated key
		 */
		for (int i = 0; i < 5; i++) {
			output[i] = (BrkeKuKemOutput) kuKem.encapsulate(publicKeys[i]);
			assertArrayEquals(((BrkeSymmetricKey) output[i].getKey()).getKeyBytes(),
					((BrkeSymmetricKey) kuKem.decapsulate(secretKeys[i], output[i].getCiphertext())).getKeyBytes());
		}

	}

	/**
	 * Tests the ECIES-Kem
	 */
	@Test
	void testEciesKem() {
		byte[] seed = { 1, 2, 3, 4, 5, 6, 7, 8, 9 };
		SecureRandom randomness = SecureRandomBuilder.createSeedableRandomness();
		randomness.setSeed(seed);
		ECIESKemFactory kemFactory = new ECIESKemFactory();
		ECIESKeyEncapsulationMechanism eciesKem = (ECIESKeyEncapsulationMechanism) kemFactory.createKem();
		ECIESKemKeyPair keyPair1 = (ECIESKemKeyPair) eciesKem.gen(randomness);
		ECIESKemKeyPair keyPair2 = (ECIESKemKeyPair) eciesKem.gen(randomness);
		ECIESKemOutput output = (ECIESKemOutput) eciesKem.encapsulate(keyPair1.getPublicKey());
		/**
		 * Decapsulating to the correct secret key should return the key, decapsulating
		 * to the wrong secret key should return a false key.
		 */
		assertArrayEquals(((BrkeSymmetricKey) output.getKey()).getKeyBytes(),
				((BrkeSymmetricKey) eciesKem.decapsulate(keyPair1.getSecretKey(), output.getCiphertext()))
						.getKeyBytes());
		assertFalse(Arrays.equals(((BrkeSymmetricKey) output.getKey()).getKeyBytes(),
				((BrkeSymmetricKey) eciesKem.decapsulate(keyPair2.getSecretKey(), output.getCiphertext()))
						.getKeyBytes()));
	}

	/**
	 * Tests the BrkeInstantiation.
	 */
	@Test
	void testBrkeInstantiation() {
		/**
		 * Prepare algorithm Set.
		 */
		BrkeKuKemAssociatedDataFactory associatedDataFactory = new BrkeKuKemAssociatedDataFactory();
		BrkeKuKemFactory kuKemFactory = new BrkeKuKemFactory();
		BrkeTranscriptFactory transcriptFactory = new BrkeTranscriptFactory();
		DLPChameleonSignatureFactory signatureFactory = new DLPChameleonSignatureFactory();
		ECIESKemFactory kemFactory = new ECIESKemFactory();
		HKDFRandomOracleFactory randomOracleFactory = new HKDFRandomOracleFactory();
		AlgorithmSet1 algorithmSet = new AlgorithmSet1(kuKemFactory, kemFactory, randomOracleFactory,
				associatedDataFactory, signatureFactory, transcriptFactory);
		byte[] seed = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
		SecureRandom randomness = SecureRandomBuilder.createSeedableRandomness();
		SecureRandom randomnessA = SecureRandomBuilder.createSeedableRandomness();
		SecureRandom randomnessB = SecureRandomBuilder.createSeedableRandomness();
		randomness.setSeed(seed);
		randomnessA.setSeed(seed);
		randomnessB.setSeed(seed);

		/**
		 * Initializes both users with the same randomness
		 */
		BrkeConstruction brkeUserA = new BrkeConstruction(randomnessA, algorithmSet, true);
		BrkeConstruction brkeUserB = new BrkeConstruction(randomnessB, algorithmSet, false);

		/**
		 * Construct test associatedData
		 */
		byte[] adInput = { 1, 2, 3, 4, 5 };
		BrkeAssociatedData associatedData = new BrkeAssociatedData(adInput);
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
		long seed2 = 1785324;
		Random rng = new Random(seed2);
		/**
		 * Each user sends 20 messages, but it is randomized at which point the other
		 * user receives the next 'set' of messages. This way we can simulate
		 * asynchronous communication and see that the Brke construction achieves its
		 * purpose.
		 */
		for (int i = 0; i < 20; i++) {
			sendOutputA[i] = brkeUserA.send(randomness, associatedData);
			if (rng.nextBoolean()) {
				for (int j = lastReceivedMessageB + 1; j <= i; j++) {
					receiveOutputB[j] = brkeUserB.receive(associatedData, sendOutputA[j].getCiphertext());
				}
				lastReceivedMessageB = i;
			}
			sendOutputB[i] = brkeUserB.send(randomness, associatedData);
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
			assertArrayEquals(((BrkeSymmetricKey) sendOutputA[i].getSessionKey()).getKeyBytes(),
					((BrkeSymmetricKey) receiveOutputB[i]).getKeyBytes());
			assertArrayEquals(((BrkeSymmetricKey) sendOutputB[i].getSessionKey()).getKeyBytes(),
					((BrkeSymmetricKey) receiveOutputA[i]).getKeyBytes());
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

	/**
	 * Function to create a BrkeCiphertext to test signature.
	 * 
	 * @param randomness
	 * @return
	 */
	public BrkeCiphertext createTestCiphertextForSigning(SecureRandom randomness) {
		byte content[] = new byte[32];
		randomness.nextBytes(content);

		HibePublicParameter hibeParameter = new HibePublicParameter(content, content);
		BrkeKuKemPublicKey kukemPublicKey = new BrkeKuKemPublicKey(hibeParameter, content, 1);

		BigInteger g1 = new BigInteger(content);
		BigInteger g2 = new BigInteger(content);
		BigInteger g3 = new BigInteger(content);
		DLPChameleonVerificationKey verificationKey = new DLPChameleonVerificationKey(g1, g2, g3, content);

		ECIESKemCiphertext ciphertext = new ECIESKemCiphertext(content);

		QueuedKuKemCiphertext queuedKuKemCiphertext = new QueuedKuKemCiphertext(ciphertext, 1, null);

		return new BrkeCiphertext(1, kukemPublicKey, verificationKey, 1, queuedKuKemCiphertext);
	}

	/**
	 * Function to create a BrkeCiphertext
	 * 
	 * @param randomness
	 * @return
	 */
	public BrkeCiphertext createTestCiphertext(SecureRandom randomness, BrkeAssociatedData ad) {
		byte content[] = new byte[32];
		randomness.nextBytes(content);

		HibePublicParameter hibeParameter = new HibePublicParameter(content, content);
		BrkeKuKemPublicKey kukemPublicKey = new BrkeKuKemPublicKey(hibeParameter, content, 1);

		BigInteger g1 = new BigInteger(content);
		BigInteger g2 = new BigInteger(content);
		BigInteger g3 = new BigInteger(content);
		DLPChameleonVerificationKey verificationKey = new DLPChameleonVerificationKey(g1, g2, g3, content);

		ECIESKemCiphertext ciphertext = new ECIESKemCiphertext(content);

		QueuedKuKemCiphertext queuedKuKemCiphertext = new QueuedKuKemCiphertext(ciphertext, 1, null);
		DLPChameleonSignatureFactory signatureFactory = new DLPChameleonSignatureFactory();
		DLPChameleonOTSignatureAlgorithm signatureAlgorithm = (DLPChameleonOTSignatureAlgorithm) signatureFactory
				.createSignatureAlgorithm();
		signatureAlgorithm.init(randomness, true);
		BrkeCiphertext brkeCiphertext = new BrkeCiphertext(1, kukemPublicKey, verificationKey, 1,
				queuedKuKemCiphertext);
		brkeCiphertext.computeSignature(signatureAlgorithm, ad);
		return brkeCiphertext;
	}

}
