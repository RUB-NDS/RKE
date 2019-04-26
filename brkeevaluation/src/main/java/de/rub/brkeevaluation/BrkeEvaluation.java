package de.rub.brkeevaluation;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.security.SecureRandom;

import org.bouncycastle.util.Arrays;

import de.rub.brkeevaluation.seclevel100algorithms.AlgorithmSet100Bit;
import de.rub.brkeevaluation.seclevel100algorithms.DLPChameleon100BitSignatureFactory;
import de.rub.rke.brke.BrkeAlgorithmSet;
import de.rub.rke.brke.BrkeCiphertext;
import de.rub.rke.brke.BrkeConstruction;
import de.rub.rke.brke.BrkeSendOutput;
import de.rub.rke.queuedkukem.QueuedKuKemCiphertext;
import de.rub.rkeinstantiation.algorithmset.AlgorithmSet1;
import de.rub.rkeinstantiation.brkekem.ECIESKemCiphertext;
import de.rub.rkeinstantiation.brkekukem.BrkeKuKemPublicKey;
import de.rub.rkeinstantiation.brkesignature.DLPChameleonSignatureOutput;
import de.rub.rkeinstantiation.brkesignature.DLPChameleonVerificationKey;
import de.rub.rkeinstantiation.factories.BrkeKuKemAssociatedDataFactory;
import de.rub.rkeinstantiation.factories.BrkeKuKemFactory;
import de.rub.rkeinstantiation.factories.BrkeTranscriptFactory;
import de.rub.rkeinstantiation.factories.DLPChameleonSignatureFactory;
import de.rub.rkeinstantiation.factories.ECIESKemFactory;
import de.rub.rkeinstantiation.factories.HKDFRandomOracleFactory;
import de.rub.rkeinstantiation.hibewrapper.Hibe;
import de.rub.rkeinstantiation.utility.SecureRandomBuilder;
import de.rub.rkeinstantiation.variables.BrkeAssociatedData;
import de.rub.rkeinstantiation.variables.BrkeSymmetricKey;
import org.openjdk.jol.info.GraphLayout;

/**
 * Evaluation class for Brke AlgorithmSet1.
 * 
 * @author Marco Smeets
 *
 */
public class BrkeEvaluation {
	private static SecureRandom randomness;
	private static int securityLevel = 128;
	private static String curveidentifier;
	private final static int ITERATIONS = 50;
	private final static int NANOSEC_PER_MS = 1000000;

	/**
	 * Communication Sequences
	 */
	private final static int LOCKSTEP = 0;
	private final static int ASYNCH_WO_CROSS = 1;
	private final static int ASYNCH_WITH_CROSS = 2;
	private final static int WORSTCASE = 3;

	/**
	 * File names
	 */
	private final static String LOCKSTEP_FILE_STRING = "_LockStep_fulldata.csv";
	private final static String ASYNCH_WO_CROSS_FILE_STRING = "_AsynchWoCross_fulldata.csv";
	private final static String ASYNCH_WITH_CROSS_FILE_STRING = "_AsynchWithCross_fulldata.csv";
	private final static String WORSTCASE_FILE_STRING = "_WorstCase_fulldata.csv";

	/**
	 * Lockstep communication variables
	 */
	private final static int LOCKSTEP_COMMUNICATIONSTEPS = 4;
	private final static int LOCKSTEP_CIPHERTEXTS = 2;
	private final static String LOCKSTEP_FILE_BEGINNING = "Iteration;Step 0;Step 1;Step 2;Step 3;kuKemCiphertext size 0;kuKemCiphertext size 1;UserstateA size;UserstateB size";

	/**
	 * Asynchronous communication with/without crossing messages variables
	 */
	private final static int ASYNCH_COMMUNICATIONSTEPS = 10;
	private final static int ASYNCH_CIPHERTEXTS = 5;
	private final static String ASYNCH_FILE_BEGINNING = "Iteration;Step 0;Step 1;Step 2;Step 3;Step 4;Step 5;Step 6;Step 7;Step 8;Step 9;kuKemCiphertext size 0;kuKemCiphertext size 1;kuKemCiphertext size 2;kuKemCiphertext size 3;kuKemCiphertext size 4;Userstate diff 0;Userstate diff 1;Userstate diff 2;Userstate diff 3;Userstate diff 4;Userstate diff 5;Userstate diff 6;Userstate diff 7;Userstate diff 8;Userstate diff 9";
	private final static int ASYNCH_BRKE_OUTPUT_A = 3;
	private final static int ASYNCH_BRKE_OUTPUT_B = 2;

	/**
	 * 'Worst Case' communication variables
	 */
	private final static int WORSTCASE_COMMUNICATIONSTEPS = 16;
	private final static int WORSTCASE_CIPHERTEXTS = 8;
	private final static String WORSTCASE_FILE_BEGINNING = "Iteration;Step 0;Step 1;Step 2;Step 3;Step 4;Step 5;Step 6;Step 7;Step 8;Step 9;Step 10;Step 11;Step 12;Step 13;Step 14;Step 15;kuKemCiphertext size 0;kuKemCiphertext size 1;kuKemCiphertext size 2;kuKemCiphertext size 3;kuKemCiphertext size 4;kuKemCiphertext size 5;kuKemCiphertext size 6;kuKemCiphertext size 7;Userstate diff 0;Userstate diff 1;Userstate diff 2;Userstate diff 3;Userstate diff 4;Userstate diff 5;Userstate diff 6;Userstate diff 7;Userstate diff 8;Userstate diff 9";
	private final static int WORSTCASE_BRKE_OUTPUT_A = 6;
	private final static int WORSTCASE_BRKE_OUTPUT_B = 2;

	private final static int BNP256_B12P381_FIELD_ELEMENT_SIZE = 32;
	private final static int BNP256_G1_ELEMENT_SIZE = 33;
	private final static int B12P381_G1_ELEMENT_SIZE = 49;
	private final static int B12P455_FIELD_ELEMENT_SIZE = 38;
	private final static int B12P455_G1_ELEMENT_SIZE = 58;
	private final static int BNP382_FIELD_ELEMENT_SIZE = 48;
	private final static int BNP382_G1_ELEMENT_SIZE = 49;

	public static void main(String[] args) {
		System.out.println("Evaluation of AlgortihmSet1 of the BRKE instantiation");
		randomness = new SecureRandom();
		detectHibeSizes();

		System.out.println();
		System.out.println("Testing different communication sequences:");

		testCommunicationSequence(LOCKSTEP);
		testCommunicationSequence(ASYNCH_WO_CROSS);
		testCommunicationSequence(ASYNCH_WITH_CROSS);
		testCommunicationSequence(WORSTCASE);
	}

	/**
	 * Test lock step communication
	 * 
	 * @param iterations - number of test iterations
	 */
	static void testCommunicationSequence(int communicationSequence) {
		printCommunicationSequence(communicationSequence);
		/**
		 * Initialize BrkeAlgorithmSet for security level
		 */
		BrkeAlgorithmSet algorithmSet;
		ECIESKemFactory kemFactory = new ECIESKemFactory();
		BrkeKuKemAssociatedDataFactory associatedDataFactory = new BrkeKuKemAssociatedDataFactory();
		BrkeKuKemFactory kuKemFactory = new BrkeKuKemFactory();
		BrkeTranscriptFactory transcriptFactory = new BrkeTranscriptFactory();
		HKDFRandomOracleFactory randomOracleFactory = new HKDFRandomOracleFactory();
		if (securityLevel == 100) {
			DLPChameleon100BitSignatureFactory signatureFactory = new DLPChameleon100BitSignatureFactory();
			algorithmSet = new AlgorithmSet100Bit(kuKemFactory, kemFactory, randomOracleFactory, associatedDataFactory,
					signatureFactory, transcriptFactory);
		} else {
			DLPChameleonSignatureFactory signatureFactory = new DLPChameleonSignatureFactory();
			algorithmSet = new AlgorithmSet1(kuKemFactory, kemFactory, randomOracleFactory, associatedDataFactory,
					signatureFactory, transcriptFactory);
		}
		/**
		 * Initialize two Brke users
		 */
		byte[] seed = new byte[32];
		randomness.nextBytes(seed);
		SecureRandom initialRandomnessA = SecureRandomBuilder.createSeedableRandomness();
		SecureRandom initialRandomnessB = SecureRandomBuilder.createSeedableRandomness();
		initialRandomnessA.setSeed(seed);
		initialRandomnessB.setSeed(seed);
		BrkeAssociatedData ad = new BrkeAssociatedData(seed);
		BrkeConstruction brkeUserA = new BrkeConstruction(initialRandomnessA, algorithmSet, true);
		BrkeConstruction brkeUserB = new BrkeConstruction(initialRandomnessB, algorithmSet, false);

		/**
		 * Reset File
		 */
		initializeCSVFile(communicationSequence);

		/**
		 * Naming is corresponding to communication sequence numbers
		 */
		int communicationsteps = 0;
		int ciphertexts = 0;
		switch (communicationSequence) {
		case LOCKSTEP:
			communicationsteps = LOCKSTEP_COMMUNICATIONSTEPS;
			ciphertexts = LOCKSTEP_CIPHERTEXTS;
			break;
		case ASYNCH_WO_CROSS:
			communicationsteps = ASYNCH_COMMUNICATIONSTEPS;
			ciphertexts = ASYNCH_CIPHERTEXTS;
			break;
		case ASYNCH_WITH_CROSS:
			communicationsteps = ASYNCH_COMMUNICATIONSTEPS;
			ciphertexts = ASYNCH_CIPHERTEXTS;
			break;
		case WORSTCASE:
			communicationsteps = WORSTCASE_COMMUNICATIONSTEPS;
			ciphertexts = WORSTCASE_CIPHERTEXTS;
			break;
		}
		long startTime[] = new long[communicationsteps];
		long endTime[] = new long[communicationsteps];
		long sumTime[] = new long[communicationsteps];
		for (int i = 0; i < communicationsteps; i++) {
			sumTime[i] = 0;
		}
		long startSize[] = new long[communicationsteps];
		long endSize[] = new long[communicationsteps];
		long sumSize[] = new long[communicationsteps];
		for (int i = 0; i < communicationsteps; i++) {
			sumSize[i] = 0;
		}

		BrkeCiphertext ciphertext[] = new BrkeCiphertext[ciphertexts];
		long kukemCiphertextSize[][] = new long[ciphertexts][ITERATIONS + 1];

		switch (communicationSequence) {
		case LOCKSTEP:
			performLockstep(brkeUserA, brkeUserB, ad, startTime, endTime, sumTime, startSize, endSize, sumSize,
					ciphertext, kukemCiphertextSize);
			break;
		case ASYNCH_WO_CROSS:
			performAsynchWOCross(brkeUserA, brkeUserB, ad, startTime, endTime, sumTime, startSize, endSize, sumSize,
					ciphertext, kukemCiphertextSize);
			break;
		case ASYNCH_WITH_CROSS:
			performAsynchWithCross(brkeUserA, brkeUserB, ad, startTime, endTime, sumTime, startSize, endSize, sumSize,
					ciphertext, kukemCiphertextSize);
			break;
		case WORSTCASE:
			performWorstCase(brkeUserA, brkeUserB, ad, startTime, endTime, sumTime, startSize, endSize, sumSize,
					ciphertext, kukemCiphertextSize);
			break;
		}
	}

	private static void performLockstep(BrkeConstruction brkeUserA, BrkeConstruction brkeUserB, BrkeAssociatedData ad,
			long[] startTime, long[] endTime, long[] sumTime, long[] startSize, long[] endSize, long[] sumSize,
			BrkeCiphertext ciphertext[], long kukemCiphertextSize[][]) {
		BrkeSendOutput sendOutputA;
		BrkeSendOutput sendOutputB;
		BrkeSymmetricKey sessionKeyA;
		BrkeSymmetricKey sessionKeyB;

		System.out.println("Userstate A size before communication: " + GraphLayout.parseInstance(brkeUserA).totalSize()
				+ " byte.");
		System.out.println("Userstate B size before communication: " + GraphLayout.parseInstance(brkeUserB).totalSize()
				+ " byte.");

		/**
		 * Do one more iteration, because first communication round is always different.
		 * We save the data of the first iteration in the files, but do not consider
		 * them when computing the average.
		 */
		for (int i = 0; i < ITERATIONS + 1; i++) {
			/**
			 * Measure time for the communication sequence. Check if session keys are
			 * matching to ensure correct sequence.
			 */
			startSize[0] = GraphLayout.parseInstance(brkeUserA).totalSize();
			startTime[0] = System.nanoTime();
			sendOutputA = brkeUserA.send(randomness, ad);
			endTime[0] = System.nanoTime();
			endSize[0] = GraphLayout.parseInstance(brkeUserA).totalSize();

			startSize[1] = GraphLayout.parseInstance(brkeUserB).totalSize();
			startTime[1] = System.nanoTime();
			sessionKeyB = (BrkeSymmetricKey) brkeUserB.receive(ad, sendOutputA.getCiphertext());
			endTime[1] = System.nanoTime();
			endSize[1] = GraphLayout.parseInstance(brkeUserB).totalSize();

			startSize[2] = GraphLayout.parseInstance(brkeUserB).totalSize();
			startTime[2] = System.nanoTime();
			sendOutputB = brkeUserB.send(randomness, ad);
			endTime[2] = System.nanoTime();
			endSize[2] = GraphLayout.parseInstance(brkeUserB).totalSize();

			startSize[3] = GraphLayout.parseInstance(brkeUserA).totalSize();
			startTime[3] = System.nanoTime();
			sessionKeyA = (BrkeSymmetricKey) brkeUserA.receive(ad, sendOutputB.getCiphertext());
			endTime[3] = System.nanoTime();
			endSize[3] = GraphLayout.parseInstance(brkeUserA).totalSize();

			/**
			 * Ensure that A->B session keys are equal
			 */

			if (!Arrays.areEqual(((BrkeSymmetricKey) sendOutputA.getSessionKey()).getKeyBytes(),
					sessionKeyB.getKeyBytes())) {
				System.out.println("A->B session key is not equal!");
			}

			/**
			 * Ensure that B->A session keys are equal
			 */

			if (!Arrays.areEqual(((BrkeSymmetricKey) sendOutputB.getSessionKey()).getKeyBytes(),
					sessionKeyA.getKeyBytes())) {
				System.out.println("B->A session key is not equal!");
			}

			/**
			 * Get ciphertext
			 */
			ciphertext[0] = sendOutputA.getCiphertext();
			ciphertext[1] = sendOutputB.getCiphertext();

			/**
			 * Get KuKem ciphertext size
			 */
			kukemCiphertextSize[0][i] = getKuKemCiphertextSize(ciphertext[0]);
			kukemCiphertextSize[1][i] = getKuKemCiphertextSize(ciphertext[1]);

			if (i != 0) {
				/**
				 * Sum of the measurements
				 */
				for (int j = 0; j < LOCKSTEP_COMMUNICATIONSTEPS; j++) {
					sumTime[j] = sumTime[j] + ((endTime[j] - startTime[j]) / NANOSEC_PER_MS);
					sumSize[j] = sumSize[j] + (endSize[j] - startSize[j]);
				}
			}

			/**
			 * Print data of every iteration to a csv file.
			 */
			try {
				BufferedWriter writer = new BufferedWriter(
						new FileWriter(curveidentifier + "_LockStep_fulldata.csv", true));
				String output = i + ";";
				for (int j = 0; j < LOCKSTEP_COMMUNICATIONSTEPS; j++) {
					output += ((endTime[j] - startTime[j]) / NANOSEC_PER_MS) + ";";
				}
				for (int j = 0; j < LOCKSTEP_CIPHERTEXTS; j++) {
					output += kukemCiphertextSize[j][i] + ";";
				}
				for (int j = 0; j < LOCKSTEP_COMMUNICATIONSTEPS; j++) {
					output += (endSize[j] - startSize[j]) + ";";
				}
				writer.append(output);
				writer.newLine();
				writer.close();
			} catch (IOException e) {
			}
		}
		printResults(LOCKSTEP, sumTime, sumSize, ciphertext, kukemCiphertextSize);
	}

	private static void performAsynchWOCross(BrkeConstruction brkeUserA, BrkeConstruction brkeUserB,
			BrkeAssociatedData ad, long[] startTime, long[] endTime, long[] sumTime, long[] startSize, long[] endSize,
			long[] sumSize, BrkeCiphertext ciphertext[], long kukemCiphertextSize[][]) {
		BrkeSendOutput sendOutputA[] = new BrkeSendOutput[ASYNCH_BRKE_OUTPUT_A];
		BrkeSendOutput sendOutputB[] = new BrkeSendOutput[ASYNCH_BRKE_OUTPUT_B];

		BrkeSymmetricKey sessionKeyA[] = new BrkeSymmetricKey[ASYNCH_BRKE_OUTPUT_B];
		BrkeSymmetricKey sessionKeyB[] = new BrkeSymmetricKey[ASYNCH_BRKE_OUTPUT_A];

		System.out.println("Userstate A size before communication: " + GraphLayout.parseInstance(brkeUserA).totalSize()
				+ " byte.");
		System.out.println("Userstate B size before communication: " + GraphLayout.parseInstance(brkeUserB).totalSize()
				+ " byte.");

		for (int i = 0; i < ITERATIONS + 1; i++) {
			/**
			 * Measure time for the communication sequence. Check if session keys are
			 * matching to ensure correct sequence.
			 */

			/**
			 * Step 0 and 1
			 */
			startSize[0] = GraphLayout.parseInstance(brkeUserA).totalSize();
			startTime[0] = System.nanoTime();
			sendOutputA[0] = brkeUserA.send(randomness, ad);
			endTime[0] = System.nanoTime();
			endSize[0] = GraphLayout.parseInstance(brkeUserA).totalSize();

			startSize[1] = GraphLayout.parseInstance(brkeUserB).totalSize();
			startTime[1] = System.nanoTime();
			sessionKeyB[0] = (BrkeSymmetricKey) brkeUserB.receive(ad, sendOutputA[0].getCiphertext());
			endTime[1] = System.nanoTime();
			endSize[1] = GraphLayout.parseInstance(brkeUserB).totalSize();

			/**
			 * Step 2 and 3
			 */
			startSize[2] = GraphLayout.parseInstance(brkeUserA).totalSize();
			startTime[2] = System.nanoTime();
			sendOutputA[1] = brkeUserA.send(randomness, ad);
			endTime[2] = System.nanoTime();
			endSize[2] = GraphLayout.parseInstance(brkeUserA).totalSize();

			startSize[3] = GraphLayout.parseInstance(brkeUserB).totalSize();
			startTime[3] = System.nanoTime();
			sessionKeyB[1] = (BrkeSymmetricKey) brkeUserB.receive(ad, sendOutputA[1].getCiphertext());
			endTime[3] = System.nanoTime();
			endSize[3] = GraphLayout.parseInstance(brkeUserB).totalSize();

			/**
			 * Step 4 and 5
			 */
			startSize[4] = GraphLayout.parseInstance(brkeUserA).totalSize();
			startTime[4] = System.nanoTime();
			sendOutputA[2] = brkeUserA.send(randomness, ad);
			endTime[4] = System.nanoTime();
			endSize[4] = GraphLayout.parseInstance(brkeUserA).totalSize();

			startSize[5] = GraphLayout.parseInstance(brkeUserB).totalSize();
			startTime[5] = System.nanoTime();
			sessionKeyB[2] = (BrkeSymmetricKey) brkeUserB.receive(ad, sendOutputA[2].getCiphertext());
			endTime[5] = System.nanoTime();
			endSize[5] = GraphLayout.parseInstance(brkeUserB).totalSize();

			/**
			 * Step 6 and 7
			 */
			startSize[6] = GraphLayout.parseInstance(brkeUserB).totalSize();
			startTime[6] = System.nanoTime();
			sendOutputB[0] = brkeUserB.send(randomness, ad);
			endTime[6] = System.nanoTime();
			endSize[6] = GraphLayout.parseInstance(brkeUserB).totalSize();

			startSize[7] = GraphLayout.parseInstance(brkeUserA).totalSize();
			startTime[7] = System.nanoTime();
			sessionKeyA[0] = (BrkeSymmetricKey) brkeUserA.receive(ad, sendOutputB[0].getCiphertext());
			endTime[7] = System.nanoTime();
			endSize[7] = GraphLayout.parseInstance(brkeUserA).totalSize();
			/**
			 * Step 8 and 9
			 */
			startSize[8] = GraphLayout.parseInstance(brkeUserB).totalSize();
			startTime[8] = System.nanoTime();
			sendOutputB[1] = brkeUserB.send(randomness, ad);
			endTime[8] = System.nanoTime();
			endSize[8] = GraphLayout.parseInstance(brkeUserB).totalSize();

			startSize[9] = GraphLayout.parseInstance(brkeUserA).totalSize();
			startTime[9] = System.nanoTime();
			sessionKeyA[1] = (BrkeSymmetricKey) brkeUserA.receive(ad, sendOutputB[1].getCiphertext());
			endTime[9] = System.nanoTime();
			endSize[9] = GraphLayout.parseInstance(brkeUserA).totalSize();

			/**
			 * Ensure that A->B session keys are equal
			 */
			for (int j = 0; j < 3; j++) {
				if (!Arrays.areEqual(((BrkeSymmetricKey) sendOutputA[j].getSessionKey()).getKeyBytes(),
						sessionKeyB[j].getKeyBytes())) {
					System.out.println("A->B session key is not equal!");
				}
			}
			/**
			 * Ensure that B->A session keys are equal
			 */
			for (int j = 0; j < 2; j++) {
				if (!Arrays.areEqual(((BrkeSymmetricKey) sendOutputB[j].getSessionKey()).getKeyBytes(),
						sessionKeyA[j].getKeyBytes())) {
					System.out.println("B->A session key is not equal!");
				}
			}

			/**
			 * Get ciphertext
			 */
			ciphertext[0] = sendOutputA[0].getCiphertext();
			ciphertext[1] = sendOutputA[1].getCiphertext();
			ciphertext[2] = sendOutputA[2].getCiphertext();
			ciphertext[3] = sendOutputB[0].getCiphertext();
			ciphertext[4] = sendOutputB[1].getCiphertext();

			/**
			 * Get KuKem ciphertext size
			 */
			for (int j = 0; j < ASYNCH_CIPHERTEXTS; j++) {
				kukemCiphertextSize[j][i] = getKuKemCiphertextSize(ciphertext[j]);
			}

			/**
			 * Sum of the measurements
			 */
			if (i != 0) {
				/**
				 * Sum of the measurements
				 */
				for (int j = 0; j < ASYNCH_COMMUNICATIONSTEPS; j++) {
					sumTime[j] = sumTime[j] + ((endTime[j] - startTime[j]) / NANOSEC_PER_MS);
					sumSize[j] = sumSize[j] + (endSize[j] - startSize[j]);
				}
			}

			/**
			 * Print data of every iteration to a csv file.
			 */
			try {
				BufferedWriter writer = new BufferedWriter(
						new FileWriter(curveidentifier + "_AsynchWoCross_fulldata.csv", true));
				String output = i + ";";
				for (int j = 0; j < ASYNCH_COMMUNICATIONSTEPS; j++) {
					output += ((endTime[j] - startTime[j]) / NANOSEC_PER_MS) + ";";
				}
				for (int j = 0; j < ASYNCH_CIPHERTEXTS; j++) {
					output += kukemCiphertextSize[j][i] + ";";
				}
				for (int j = 0; j < ASYNCH_COMMUNICATIONSTEPS; j++) {
					output += (endSize[j] - startSize[j]) + ";";
				}
				writer.append(output);
				writer.newLine();
				writer.close();
			} catch (IOException e) {
			}
		}
		printResults(ASYNCH_WO_CROSS, sumTime, sumSize, ciphertext, kukemCiphertextSize);
	}

	private static void performAsynchWithCross(BrkeConstruction brkeUserA, BrkeConstruction brkeUserB,
			BrkeAssociatedData ad, long[] startTime, long[] endTime, long[] sumTime, long[] startSize, long[] endSize,
			long[] sumSize, BrkeCiphertext ciphertext[], long kukemCiphertextSize[][]) {
		BrkeSendOutput sendOutputA[] = new BrkeSendOutput[ASYNCH_BRKE_OUTPUT_A];
		BrkeSendOutput sendOutputB[] = new BrkeSendOutput[ASYNCH_BRKE_OUTPUT_A];

		BrkeSymmetricKey sessionKeyA[] = new BrkeSymmetricKey[ASYNCH_BRKE_OUTPUT_A];
		BrkeSymmetricKey sessionKeyB[] = new BrkeSymmetricKey[ASYNCH_BRKE_OUTPUT_A];

		System.out.println("Userstate A size before communication: " + GraphLayout.parseInstance(brkeUserA).totalSize()
				+ " byte.");
		System.out.println("Userstate B size before communication: " + GraphLayout.parseInstance(brkeUserB).totalSize()
				+ " byte.");

		for (int i = 0; i < ITERATIONS + 1; i++) {
			/**
			 * Measure time for the communication sequence. Check if session keys are
			 * matching to ensure correct sequence.
			 */

			/**
			 * Step 0
			 */
			startSize[0] = GraphLayout.parseInstance(brkeUserA).totalSize();
			startTime[0] = System.nanoTime();
			sendOutputA[0] = brkeUserA.send(randomness, ad);
			endTime[0] = System.nanoTime();
			endSize[0] = GraphLayout.parseInstance(brkeUserA).totalSize();

			/**
			 * Step 1
			 */
			startSize[1] = GraphLayout.parseInstance(brkeUserA).totalSize();
			startTime[1] = System.nanoTime();
			sendOutputA[1] = brkeUserA.send(randomness, ad);
			endTime[1] = System.nanoTime();
			endSize[1] = GraphLayout.parseInstance(brkeUserA).totalSize();

			/**
			 * Step 2
			 */
			startSize[2] = GraphLayout.parseInstance(brkeUserB).totalSize();
			startTime[2] = System.nanoTime();
			sendOutputB[0] = brkeUserB.send(randomness, ad);
			endTime[2] = System.nanoTime();
			endSize[2] = GraphLayout.parseInstance(brkeUserB).totalSize();

			/**
			 * Step 3
			 */
			startSize[3] = GraphLayout.parseInstance(brkeUserB).totalSize();
			startTime[3] = System.nanoTime();
			sendOutputB[1] = brkeUserB.send(randomness, ad);
			endTime[3] = System.nanoTime();
			endSize[3] = GraphLayout.parseInstance(brkeUserB).totalSize();

			/**
			 * Step 4
			 */
			startSize[4] = GraphLayout.parseInstance(brkeUserA).totalSize();
			startTime[4] = System.nanoTime();
			sessionKeyA[0] = (BrkeSymmetricKey) brkeUserA.receive(ad, sendOutputB[0].getCiphertext());
			endTime[4] = System.nanoTime();
			endSize[4] = GraphLayout.parseInstance(brkeUserA).totalSize();

			/**
			 * Step 5
			 */
			startSize[5] = GraphLayout.parseInstance(brkeUserA).totalSize();
			startTime[5] = System.nanoTime();
			sendOutputA[2] = brkeUserA.send(randomness, ad);
			endTime[5] = System.nanoTime();
			endSize[5] = GraphLayout.parseInstance(brkeUserA).totalSize();

			/**
			 * Step 6
			 */
			startSize[6] = GraphLayout.parseInstance(brkeUserB).totalSize();
			startTime[6] = System.nanoTime();
			sessionKeyB[0] = (BrkeSymmetricKey) brkeUserB.receive(ad, sendOutputA[0].getCiphertext());
			endTime[6] = System.nanoTime();
			endSize[6] = GraphLayout.parseInstance(brkeUserB).totalSize();

			/**
			 * Step 7
			 */
			startSize[7] = GraphLayout.parseInstance(brkeUserB).totalSize();
			startTime[7] = System.nanoTime();
			sessionKeyB[1] = (BrkeSymmetricKey) brkeUserB.receive(ad, sendOutputA[1].getCiphertext());
			endTime[7] = System.nanoTime();
			endSize[7] = GraphLayout.parseInstance(brkeUserB).totalSize();

			/**
			 * Step 8
			 */
			startSize[8] = GraphLayout.parseInstance(brkeUserB).totalSize();
			startTime[8] = System.nanoTime();
			sessionKeyB[2] = (BrkeSymmetricKey) brkeUserB.receive(ad, sendOutputA[2].getCiphertext());
			endTime[8] = System.nanoTime();
			endSize[8] = GraphLayout.parseInstance(brkeUserB).totalSize();

			/**
			 * Step 9
			 */
			startSize[9] = GraphLayout.parseInstance(brkeUserA).totalSize();
			startTime[9] = System.nanoTime();
			sessionKeyA[1] = (BrkeSymmetricKey) brkeUserA.receive(ad, sendOutputB[1].getCiphertext());
			endTime[9] = System.nanoTime();
			endSize[9] = GraphLayout.parseInstance(brkeUserA).totalSize();

			/**
			 * Ensure that A->B session keys are equal
			 */
			for (int j = 0; j < 3; j++) {
				if (!Arrays.areEqual(((BrkeSymmetricKey) sendOutputA[j].getSessionKey()).getKeyBytes(),
						sessionKeyB[j].getKeyBytes())) {
					System.out.println("A->B session key is not equal!");
				}
			}
			/**
			 * Ensure that B->A session keys are equal
			 */
			for (int j = 0; j < 2; j++) {
				if (!Arrays.areEqual(((BrkeSymmetricKey) sendOutputB[j].getSessionKey()).getKeyBytes(),
						sessionKeyA[j].getKeyBytes())) {
					System.out.println("B->A session key is not equal!");
				}
			}

			/**
			 * Get ciphertext
			 */
			ciphertext[0] = sendOutputA[0].getCiphertext();
			ciphertext[1] = sendOutputA[1].getCiphertext();
			ciphertext[2] = sendOutputB[0].getCiphertext();
			ciphertext[3] = sendOutputB[1].getCiphertext();
			ciphertext[4] = sendOutputA[2].getCiphertext();

			/**
			 * Get KuKem ciphertext size
			 */
			for (int j = 0; j < ASYNCH_CIPHERTEXTS; j++) {
				kukemCiphertextSize[j][i] = getKuKemCiphertextSize(ciphertext[j]);
			}

			/**
			 * Sum of the measurements
			 */
			if (i != 0) {
				for (int j = 0; j < ASYNCH_COMMUNICATIONSTEPS; j++) {
					sumTime[j] = sumTime[j] + ((endTime[j] - startTime[j]) / NANOSEC_PER_MS);
					sumSize[j] = sumSize[j] + (endSize[j] - startSize[j]);
				}
			}

			/**
			 * Print data of every iteration to a csv file.
			 */
			try {
				BufferedWriter writer = new BufferedWriter(
						new FileWriter(curveidentifier + "_AsynchWithCross_fulldata.csv", true));
				String output = i + ";";
				for (int j = 0; j < ASYNCH_COMMUNICATIONSTEPS; j++) {
					output += ((endTime[j] - startTime[j]) / NANOSEC_PER_MS) + ";";
				}
				for (int j = 0; j < ASYNCH_CIPHERTEXTS; j++) {
					output += kukemCiphertextSize[j][i] + ";";
				}
				for (int j = 0; j < ASYNCH_COMMUNICATIONSTEPS; j++) {
					output += (endSize[j] - startSize[j]) + ";";
				}
				writer.append(output);
				writer.newLine();
				writer.close();
			} catch (IOException e) {
			}
		}
		printResults(ASYNCH_WITH_CROSS, sumTime, sumSize, ciphertext, kukemCiphertextSize);
	}

	private static void performWorstCase(BrkeConstruction brkeUserA, BrkeConstruction brkeUserB, BrkeAssociatedData ad,
			long[] startTime, long[] endTime, long[] sumTime, long[] startSize, long[] endSize, long[] sumSize,
			BrkeCiphertext ciphertext[], long kukemCiphertextSize[][]) {
		BrkeSendOutput sendOutputA[] = new BrkeSendOutput[WORSTCASE_BRKE_OUTPUT_A];
		BrkeSendOutput sendOutputB[] = new BrkeSendOutput[WORSTCASE_BRKE_OUTPUT_B];

		BrkeSymmetricKey sessionKeyA[] = new BrkeSymmetricKey[WORSTCASE_BRKE_OUTPUT_B];
		BrkeSymmetricKey sessionKeyB[] = new BrkeSymmetricKey[WORSTCASE_BRKE_OUTPUT_A];

		System.out.println("Userstate A size before communication: " + GraphLayout.parseInstance(brkeUserA).totalSize()
				+ " byte.");
		System.out.println("Userstate B size before communication: " + GraphLayout.parseInstance(brkeUserB).totalSize()
				+ " byte.");

		for (int i = 0; i < ITERATIONS + 1; i++) {
			/**
			 * Measure time for the communication sequence. Check if session keys are
			 * matching to ensure correct sequence.
			 */

			/**
			 * Step 0
			 */
			startSize[0] = GraphLayout.parseInstance(brkeUserA).totalSize();
			startTime[0] = System.nanoTime();
			sendOutputA[0] = brkeUserA.send(randomness, ad);
			endTime[0] = System.nanoTime();
			endSize[0] = GraphLayout.parseInstance(brkeUserA).totalSize();

			/**
			 * Step 1
			 */
			startSize[1] = GraphLayout.parseInstance(brkeUserA).totalSize();
			startTime[1] = System.nanoTime();
			sendOutputA[1] = brkeUserA.send(randomness, ad);
			endTime[1] = System.nanoTime();
			endSize[1] = GraphLayout.parseInstance(brkeUserA).totalSize();

			/**
			 * Step 2
			 */
			startSize[2] = GraphLayout.parseInstance(brkeUserA).totalSize();
			startTime[2] = System.nanoTime();
			sendOutputA[2] = brkeUserA.send(randomness, ad);
			endTime[2] = System.nanoTime();
			endSize[2] = GraphLayout.parseInstance(brkeUserA).totalSize();

			/**
			 * Step 3
			 */
			startSize[3] = GraphLayout.parseInstance(brkeUserA).totalSize();
			startTime[3] = System.nanoTime();
			sendOutputA[3] = brkeUserA.send(randomness, ad);
			endTime[3] = System.nanoTime();
			endSize[3] = GraphLayout.parseInstance(brkeUserA).totalSize();

			/**
			 * Step 4
			 */
			startSize[4] = GraphLayout.parseInstance(brkeUserA).totalSize();
			startTime[4] = System.nanoTime();
			sendOutputA[4] = brkeUserA.send(randomness, ad);
			endTime[4] = System.nanoTime();
			endSize[4] = GraphLayout.parseInstance(brkeUserA).totalSize();

			/**
			 * Step 5
			 */
			startSize[5] = GraphLayout.parseInstance(brkeUserB).totalSize();
			startTime[5] = System.nanoTime();
			sendOutputB[0] = brkeUserB.send(randomness, ad);
			endTime[5] = System.nanoTime();
			endSize[5] = GraphLayout.parseInstance(brkeUserB).totalSize();

			/**
			 * Step 6
			 */
			startSize[6] = GraphLayout.parseInstance(brkeUserA).totalSize();
			startTime[6] = System.nanoTime();
			sessionKeyA[0] = (BrkeSymmetricKey) brkeUserA.receive(ad, sendOutputB[0].getCiphertext());
			endTime[6] = System.nanoTime();
			endSize[6] = GraphLayout.parseInstance(brkeUserA).totalSize();

			/**
			 * Step 7
			 */
			startSize[7] = GraphLayout.parseInstance(brkeUserB).totalSize();
			startTime[7] = System.nanoTime();
			sendOutputB[1] = brkeUserB.send(randomness, ad);
			endTime[7] = System.nanoTime();
			endSize[7] = GraphLayout.parseInstance(brkeUserB).totalSize();

			/**
			 * Step 8
			 */
			startSize[8] = GraphLayout.parseInstance(brkeUserA).totalSize();
			startTime[8] = System.nanoTime();
			sessionKeyA[1] = (BrkeSymmetricKey) brkeUserA.receive(ad, sendOutputB[1].getCiphertext());
			endTime[8] = System.nanoTime();
			endSize[8] = GraphLayout.parseInstance(brkeUserA).totalSize();

			/**
			 * Step 9
			 */
			startSize[9] = GraphLayout.parseInstance(brkeUserA).totalSize();
			startTime[9] = System.nanoTime();
			sendOutputA[5] = brkeUserA.send(randomness, ad);
			endTime[9] = System.nanoTime();
			endSize[9] = GraphLayout.parseInstance(brkeUserA).totalSize();

			/**
			 * Step 10-15
			 */
			for (int j = 10; j < 16; j++) {
				startSize[j] = GraphLayout.parseInstance(brkeUserB).totalSize();
				startTime[j] = System.nanoTime();
				sessionKeyB[j - 10] = (BrkeSymmetricKey) brkeUserB.receive(ad, sendOutputA[j - 10].getCiphertext());
				endTime[j] = System.nanoTime();
				endSize[j] = GraphLayout.parseInstance(brkeUserB).totalSize();
			}

			/**
			 * Ensure that A->B session keys are equal
			 */
			for (int j = 0; j < 6; j++) {
				if (!Arrays.areEqual(((BrkeSymmetricKey) sendOutputA[j].getSessionKey()).getKeyBytes(),
						sessionKeyB[j].getKeyBytes())) {
					System.out.println("A->B session key is not equal at :" + j);
				}
			}

			/**
			 * Ensure that B->A session keys are equal
			 */
			for (int j = 0; j < 2; j++) {
				if (!Arrays.areEqual(((BrkeSymmetricKey) sendOutputB[j].getSessionKey()).getKeyBytes(),
						sessionKeyA[j].getKeyBytes())) {
					System.out.println("B->A session key is not equal at" + j);
				}
			}

			/**
			 * Get ciphertext
			 */
			ciphertext[0] = sendOutputA[0].getCiphertext();
			ciphertext[1] = sendOutputA[1].getCiphertext();
			ciphertext[2] = sendOutputA[2].getCiphertext();
			ciphertext[3] = sendOutputA[3].getCiphertext();
			ciphertext[4] = sendOutputA[4].getCiphertext();
			ciphertext[5] = sendOutputB[0].getCiphertext();
			ciphertext[6] = sendOutputB[1].getCiphertext();
			ciphertext[7] = sendOutputA[5].getCiphertext();

			/**
			 * Get KuKem ciphertext size
			 */
			for (int j = 0; j < WORSTCASE_CIPHERTEXTS; j++) {
				kukemCiphertextSize[j][i] = getKuKemCiphertextSize(ciphertext[j]);
			}

			/**
			 * Sum of the measurements
			 */
			if (i != 0) {
				/**
				 * Sum of the measurements
				 */
				for (int j = 0; j < WORSTCASE_COMMUNICATIONSTEPS; j++) {
					sumTime[j] = sumTime[j] + ((endTime[j] - startTime[j]) / NANOSEC_PER_MS);
					sumSize[j] = sumSize[j] + (endSize[j] - startSize[j]);
				}
			}

			/**
			 * Print data of every iteration to a csv file.
			 */
			try {
				BufferedWriter writer = new BufferedWriter(
						new FileWriter(curveidentifier + "_WorstCase_fulldata.csv", true));
				String output = i + ";";
				for (int j = 0; j < WORSTCASE_COMMUNICATIONSTEPS; j++) {
					output += ((endTime[j] - startTime[j]) / NANOSEC_PER_MS) + ";";
				}
				for (int j = 0; j < WORSTCASE_CIPHERTEXTS; j++) {
					output += kukemCiphertextSize[j][i] + ";";
				}
				for (int j = 0; j < WORSTCASE_COMMUNICATIONSTEPS; j++) {
					output += (endSize[j] - startSize[j]) + ";";
				}
				writer.append(output);
				writer.newLine();
				writer.close();
			} catch (IOException e) {
			}
		}
		printResults(WORSTCASE, sumTime, sumSize, ciphertext, kukemCiphertextSize);
	}

	private static void printResults(int communicationSequence, long[] sumTime, long[] sumSize,
			BrkeCiphertext[] ciphertext, long[][] kukemCiphertextSize) {
		int numberOfCiphertexts = 0;
		System.out.println();
		System.out.println("********************************");
		System.out.println("Average duration:");
		switch (communicationSequence) {
		case LOCKSTEP:
			System.out.println(
					"Communication step 0 - A sends    - takes: " + (sumTime[0] / ITERATIONS) + " ms on average.");
			System.out.println(
					"Communication step 1 - B receives - takes: " + (sumTime[1] / ITERATIONS) + " ms on average.");
			System.out.println(
					"Communication step 2 - B sends    - takes: " + (sumTime[2] / ITERATIONS) + " ms on average.");
			System.out.println(
					"Communication step 3 - A receives - takes: " + (sumTime[3] / ITERATIONS) + " ms on average.");

			System.out.println("********************************");
			System.out.println("Average size change:");
			System.out.println("Communication step 0 - A sends    - changes the state by: " + (sumSize[0] / ITERATIONS)
					+ " byte on average.");
			System.out.println("Communication step 1 - B receives - changes the state by: " + (sumSize[1] / ITERATIONS)
					+ " byte on average.");
			System.out.println("Communication step 2 - B sends    - changes the state by: " + (sumSize[2] / ITERATIONS)
					+ " byte on average.");
			System.out.println("Communication step 3 - A receives - changes the state by: " + (sumSize[3] / ITERATIONS)
					+ " byte on average.");
			numberOfCiphertexts = LOCKSTEP_CIPHERTEXTS;
			break;
		case ASYNCH_WO_CROSS:
			System.out.println(
					"Communication step 0 - A sends    - takes: " + (sumTime[0] / ITERATIONS) + " ms on average.");
			System.out.println(
					"Communication step 1 - B receives - takes: " + (sumTime[1] / ITERATIONS) + " ms on average.");
			System.out.println(
					"Communication step 2 - A sends    - takes: " + (sumTime[2] / ITERATIONS) + " ms on average.");
			System.out.println(
					"Communication step 3 - B receives - takes: " + (sumTime[3] / ITERATIONS) + " ms on average.");
			System.out.println(
					"Communication step 4 - A sends    - takes: " + (sumTime[4] / ITERATIONS) + " ms on average.");
			System.out.println(
					"Communication step 5 - B receives - takes: " + (sumTime[5] / ITERATIONS) + " ms on average.");
			System.out.println(
					"Communication step 6 - B sends    - takes: " + (sumTime[6] / ITERATIONS) + " ms on average.");
			System.out.println(
					"Communication step 7 - A receives - takes: " + (sumTime[7] / ITERATIONS) + " ms on average.");
			System.out.println(
					"Communication step 8 - B sends    - takes: " + (sumTime[8] / ITERATIONS) + " ms on average.");
			System.out.println(
					"Communication step 9 - A receives - takes: " + (sumTime[9] / ITERATIONS) + " ms on average.");

			System.out.println("********************************");
			System.out.println("Average size change:");
			System.out.println("Communication step 0 - A sends    - changes the state by: " + (sumSize[0] / ITERATIONS)
					+ " byte on average.");
			System.out.println("Communication step 1 - B receives - changes the state by: " + (sumSize[1] / ITERATIONS)
					+ " byte on average.");
			System.out.println("Communication step 2 - A sends    - changes the state by: " + (sumSize[2] / ITERATIONS)
					+ " byte on average.");
			System.out.println("Communication step 3 - B receives - changes the state by: " + (sumSize[3] / ITERATIONS)
					+ " byte on average.");
			System.out.println("Communication step 4 - A sends    - changes the state by: " + (sumSize[4] / ITERATIONS)
					+ " byte on average.");
			System.out.println("Communication step 5 - B receives - changes the state by: " + (sumSize[5] / ITERATIONS)
					+ " byte on average.");
			System.out.println("Communication step 6 - B sends    - changes the state by: " + (sumSize[6] / ITERATIONS)
					+ " byte on average.");
			System.out.println("Communication step 7 - A receives - changes the state by: " + (sumSize[7] / ITERATIONS)
					+ " byte on average.");
			System.out.println("Communication step 8 - B sends    - changes the state by: " + (sumSize[8] / ITERATIONS)
					+ " byte on average.");
			System.out.println("Communication step 9 - A receives - changes the state by: " + (sumSize[9] / ITERATIONS)
					+ " byte on average.");
			numberOfCiphertexts = ASYNCH_CIPHERTEXTS;
			break;
		case ASYNCH_WITH_CROSS:
			System.out.println(
					"Communication step 0 - A sends    - takes: " + (sumTime[0] / ITERATIONS) + " ms on average.");
			System.out.println(
					"Communication step 1 - A sends    - takes: " + (sumTime[1] / ITERATIONS) + " ms on average.");
			System.out.println(
					"Communication step 2 - B sends    - takes: " + (sumTime[2] / ITERATIONS) + " ms on average.");
			System.out.println(
					"Communication step 3 - B sends    - takes: " + (sumTime[3] / ITERATIONS) + " ms on average.");
			System.out.println(
					"Communication step 4 - A receives - takes: " + (sumTime[4] / ITERATIONS) + " ms on average.");
			System.out.println(
					"Communication step 5 - A sends    - takes: " + (sumTime[5] / ITERATIONS) + " ms on average.");
			System.out.println(
					"Communication step 6 - B receives - takes: " + (sumTime[6] / ITERATIONS) + " ms on average.");
			System.out.println(
					"Communication step 7 - B receives - takes: " + (sumTime[7] / ITERATIONS) + " ms on average.");
			System.out.println(
					"Communication step 8 - B receives - takes: " + (sumTime[8] / ITERATIONS) + " ms on average.");
			System.out.println(
					"Communication step 9 - A receives - takes: " + (sumTime[9] / ITERATIONS) + " ms on average.");

			System.out.println("********************************");
			System.out.println("Average size change:");
			System.out.println("Communication step 0 - A sends    - changes the state by: " + (sumSize[0] / ITERATIONS)
					+ " byte on average.");
			System.out.println("Communication step 1 - A sends    - changes the state by: " + (sumSize[1] / ITERATIONS)
					+ " byte on average.");
			System.out.println("Communication step 2 - B sends    - changes the state by: " + (sumSize[2] / ITERATIONS)
					+ " byte on average.");
			System.out.println("Communication step 3 - B sends    - changes the state by: " + (sumSize[3] / ITERATIONS)
					+ " byte on average.");
			System.out.println("Communication step 4 - A receives - changes the state by: " + (sumSize[4] / ITERATIONS)
					+ " byte on average.");
			System.out.println("Communication step 5 - B sends    - changes the state by: " + (sumSize[5] / ITERATIONS)
					+ " byte on average.");
			System.out.println("Communication step 6 - B receives - changes the state by: " + (sumSize[6] / ITERATIONS)
					+ " byte on average.");
			System.out.println("Communication step 7 - B receives - changes the state by: " + (sumSize[7] / ITERATIONS)
					+ " byte on average.");
			System.out.println("Communication step 8 - B receives - changes the state by: " + (sumSize[8] / ITERATIONS)
					+ " byte on average.");
			System.out.println("Communication step 9 - A receives - changes the state by: " + (sumSize[9] / ITERATIONS)
					+ " byte on average.");
			numberOfCiphertexts = ASYNCH_CIPHERTEXTS;
			break;
		case WORSTCASE:
			System.out.println(
					"Communication step 0 - A sends    - takes: " + (sumTime[0] / ITERATIONS) + " ms on average.");
			System.out.println(
					"Communication step 1 - A sends    - takes: " + (sumTime[1] / ITERATIONS) + " ms on average.");
			System.out.println(
					"Communication step 2 - A sends    - takes: " + (sumTime[2] / ITERATIONS) + " ms on average.");
			System.out.println(
					"Communication step 3 - A sends    - takes: " + (sumTime[3] / ITERATIONS) + " ms on average.");
			System.out.println(
					"Communication step 4 - A sends    - takes: " + (sumTime[4] / ITERATIONS) + " ms on average.");
			System.out.println(
					"Communication step 5 - B sends    - takes: " + (sumTime[5] / ITERATIONS) + " ms on average.");
			System.out.println(
					"Communication step 6 - A receives - takes: " + (sumTime[6] / ITERATIONS) + " ms on average.");
			System.out.println(
					"Communication step 7 - B sends    - takes: " + (sumTime[7] / ITERATIONS) + " ms on average.");
			System.out.println(
					"Communication step 8 - A receives - takes: " + (sumTime[8] / ITERATIONS) + " ms on average.");
			System.out.println(
					"Communication step 9 - A sends    - takes: " + (sumTime[9] / ITERATIONS) + " ms on average.");
			for (int i = 10; i < 16; i++) {
				System.out.println("Communication step " + i + " - B receives - takes: " + (sumTime[i] / ITERATIONS)
						+ " ms on average.");
			}

			System.out.println("********************************");
			System.out.println("Average size change:");
			System.out.println("Communication step 0 - A sends    - changes the state by: " + (sumSize[0] / ITERATIONS)
					+ " byte on average.");
			System.out.println("Communication step 1 - A sends    - changes the state by: " + (sumSize[1] / ITERATIONS)
					+ " byte on average.");
			System.out.println("Communication step 2 - A sends    - changes the state by: " + (sumSize[2] / ITERATIONS)
					+ " byte on average.");
			System.out.println("Communication step 3 - A sends    - changes the state by: " + (sumSize[3] / ITERATIONS)
					+ " byte on average.");
			System.out.println("Communication step 4 - A sends    - changes the state by: " + (sumSize[4] / ITERATIONS)
					+ " byte on average.");
			System.out.println("Communication step 5 - B sends    - changes the state by: " + (sumSize[5] / ITERATIONS)
					+ " byte on average.");
			System.out.println("Communication step 6 - A receives - changes the state by: " + (sumSize[6] / ITERATIONS)
					+ " byte on average.");
			System.out.println("Communication step 7 - B sends    - changes the state by: " + (sumSize[7] / ITERATIONS)
					+ " byte on average.");
			System.out.println("Communication step 8 - A receives - changes the state by: " + (sumSize[8] / ITERATIONS)
					+ " byte on average.");
			System.out.println("Communication step 9 - A sends    - changes the state by: " + (sumSize[9] / ITERATIONS)
					+ " byte on average.");
			for (int i = 10; i < 16; i++) {
				System.out.println("Communication step " + i + " - B receives - changes the state by: "
						+ (sumSize[i] / ITERATIONS) + " byte on average.");
			}
			numberOfCiphertexts = WORSTCASE_CIPHERTEXTS;
			break;
		}
		long auxilaryKuKemCiphertextSize[] = new long[numberOfCiphertexts];
		boolean constantCiphertext[] = new boolean[numberOfCiphertexts];

		/**
		 * Print Ciphertext sizes
		 */
		long baseCiphertextSize = GraphLayout.parseInstance(ciphertext[0]).totalSize()
				- kukemCiphertextSize[0][ITERATIONS];
		System.out.println();
		System.out.println("********************************");
		System.out.println("Size of ciphertexts:");
		System.out.println("Base ciphertext size (without kuKem ciphertext): " + baseCiphertextSize);
		System.out.println("Individual ciphertext parts have size:");
		printCiphertextSizes(ciphertext[0]);
		/**
		 * Check if the kuKem ciphertext is constant for one communication step
		 */
		for (int i = 0; i < numberOfCiphertexts; i++) {
			auxilaryKuKemCiphertextSize[i] = kukemCiphertextSize[i][1];
			constantCiphertext[i] = true;
		}
		for (int i = 2; i < ITERATIONS; i++) {
			for (int j = 0; j < numberOfCiphertexts; j++) {
				if (auxilaryKuKemCiphertextSize[j] != kukemCiphertextSize[j][i]) {
					constantCiphertext[j] = false;
				}
			}
		}
		/**
		 * If kuKem ciphertext is constant, print the size, otherwise refer to full
		 * data.
		 */
		for (int i = 0; i < numberOfCiphertexts; i++) {
			if (constantCiphertext[i] == true) {
				System.out.println("KuKem ciphertext size of ciphertext " + i + " is constant with "
						+ kukemCiphertextSize[i][1] + " byte.");
			} else {
				System.out.println("KuKem ciphertext size of ciphertext " + i + " is not constant. Check full data.");
			}
		}
		for (int i = 0; i < 2; i++) {
			System.out.println();
		}
	}

	private static void initializeCSVFile(int communicationSequence) {
		try {
			BufferedWriter writer = null;
			String content = null;
			switch (communicationSequence) {
			case LOCKSTEP:
				writer = new BufferedWriter(new FileWriter(curveidentifier + LOCKSTEP_FILE_STRING));
				content = LOCKSTEP_FILE_BEGINNING;
				break;
			case ASYNCH_WO_CROSS:
				writer = new BufferedWriter(new FileWriter(curveidentifier + ASYNCH_WO_CROSS_FILE_STRING));
				content = ASYNCH_FILE_BEGINNING;
				break;
			case ASYNCH_WITH_CROSS:
				writer = new BufferedWriter(new FileWriter(curveidentifier + ASYNCH_WITH_CROSS_FILE_STRING));
				content = ASYNCH_FILE_BEGINNING;
				break;
			case WORSTCASE:
				writer = new BufferedWriter(new FileWriter(curveidentifier + WORSTCASE_FILE_STRING));
				content = WORSTCASE_FILE_BEGINNING;
				break;
			}
			writer.append(content);
			writer.newLine();
			writer.close();

		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private static void printCommunicationSequence(int communicationSequence) {
		System.out.println();
		System.out.println("********************************");
		switch (communicationSequence) {
		case LOCKSTEP:
			System.out.println("Test Case 1: Lockstep communication");
			System.out.println("********************************");
			System.out.println("Communication sequence:");
			System.out.println("Sender  -> Receiver ; generated Ciphertext");
			System.out.println("A(0) -> B(1); Ciphertext 0");
			System.out.println("B(2) -> A(3); Ciphertext 1");
			System.out.println("Every message is directly received.");
			break;
		case ASYNCH_WO_CROSS:
			System.out.println("Test Case 2: Asynchronous communication without crossing messages");
			System.out.println("********************************");
			System.out.println("Communication sequence:");
			System.out.println("Sender  -> Receiver ; generated Ciphertext");
			System.out.println("A(0) -> B(1); Ciphertext 0");
			System.out.println("A(2) -> B(3); Ciphertext 1");
			System.out.println("A(4) -> B(5); Ciphertext 2");
			System.out.println("B(6) -> A(7); Ciphertext 3");
			System.out.println("B(8) -> A(9); Ciphertext 4");
			System.out.println("Every message is directly received.");
			break;
		case ASYNCH_WITH_CROSS:
			System.out.println("Test Case 3: Asynchronous communication with crossing messages");
			System.out.println("********************************");
			System.out.println("Communication sequence:");
			System.out.println("Sender  -> Receiver ; generated Ciphertext");
			System.out.println("A(0)_A0 ->        ; Ciphertext 0");
			System.out.println("A(1)_A1 ->        ; Ciphertext 1");
			System.out.println("B(2)_B0 ->        ; Ciphertext 2");
			System.out.println("B(3)_B1 ->        ; Ciphertext 3");
			System.out.println("	    -> A(4)_B0;");
			System.out.println("A(5)_A2 ->        ; Ciphertext 4");
			System.out.println("	    -> B(6)_A0;");
			System.out.println("	    -> B(7)_A1;");
			System.out.println("	    -> B(8)_A2;");
			System.out.println("	    -> A(9)_B1;");
			System.out.println("Messages cross while communicating.");
			break;
		case WORSTCASE:
			System.out.println("Test Case 4: 'Worst Case' Communication");
			System.out.println("********************************");
			System.out.println("Communication sequence:");
			System.out.println("Sender  -> Receiver ; generated Ciphertext");
			System.out.println("A(0)_A0 ->          ; Ciphertext 0");
			System.out.println("A(1)_A1 ->          ; Ciphertext 1");
			System.out.println("A(2)_A2 ->          ; Ciphertext 2");
			System.out.println("A(3)_A3 ->          ; Ciphertext 3");
			System.out.println("A(4)_A4 ->          ; Ciphertext 4");
			System.out.println("B(5)    -> A(6)     ; Ciphertext 5");
			System.out.println("B(7)    -> A(8)     ; Ciphertext 6");
			System.out.println("A(9)_A5 ->          ; Ciphertext 7");
			System.out.println("	    -> B(10)_A0  ;");
			System.out.println("	    -> B(11)_A1  ;");
			System.out.println("	    -> B(12)_A2  ;");
			System.out.println("	    -> B(13)_A3  ;");
			System.out.println("	    -> B(14)_A4  ;");
			System.out.println("	    -> B(15)_A5  ;");
			System.out.println("Messages cross while communicating.");
			break;
		}
		System.out.println("Jump to 0.");
		System.out.println("Repeat: " + ITERATIONS + " times.");

	}

	private static long getKuKemCiphertextSize(BrkeCiphertext ciphertext) {
		QueuedKuKemCiphertext queuedKuKemCiphertext = ciphertext.getCiphertext();
		if (queuedKuKemCiphertext.getKuKemCiphertexts() == null) {
			return 0;
		} else {
			return GraphLayout.parseInstance(queuedKuKemCiphertext.getKuKemCiphertexts()).totalSize();
		}
	}

	private static void printCiphertextSizes(BrkeCiphertext ciphertext) {
		BrkeKuKemPublicKey kuKemPublicKey = (BrkeKuKemPublicKey) ciphertext.getPublicKey();
		DLPChameleonVerificationKey verificationKey = (DLPChameleonVerificationKey) ciphertext.getVerificationKey();
		QueuedKuKemCiphertext queuedKuKemCiphertext = ciphertext.getCiphertext();
		ECIESKemCiphertext kemCiphertext = (ECIESKemCiphertext) queuedKuKemCiphertext.getKemCiphertext();
		DLPChameleonSignatureOutput signatureOutput = (DLPChameleonSignatureOutput) ciphertext.getSignature();
		long kuKemPublicKeySize = GraphLayout.parseInstance(kuKemPublicKey).totalSize();
		long verificationKeySize = GraphLayout.parseInstance(verificationKey).totalSize();
		long kemCiphertextSize = GraphLayout.parseInstance(kemCiphertext).totalSize();
		long signatureOutputSize = GraphLayout.parseInstance(signatureOutput).totalSize();
		long kukemCiphertextSize = getKuKemCiphertextSize(ciphertext);
		long intSize = GraphLayout.parseInstance(ciphertext).totalSize() - kuKemPublicKeySize - verificationKeySize
				- kemCiphertextSize - signatureOutputSize - kukemCiphertextSize;

		System.out.println("KuKem public key           : " + kuKemPublicKeySize + " byte.");
		System.out.println("Signature verification key : " + verificationKeySize + " byte.");
		System.out.println("Kem ciphertext             : " + kemCiphertextSize + " byte.");
		System.out.println("Signature				   : " + signatureOutputSize + " byte.");
		System.out.println("Two Integer				   : " + intSize + " byte.");
		System.out.println();
	}

	private static void detectHibeSizes() {
		/**
		 * Get the size of the elements of the elliptic curve used in the HIBE. Detect
		 * the elliptic curve and get the security level. Print the element sizes to the
		 * console. Use Size of smallest field element for the identity size.
		 */
		Hibe hibeAlgorithm = new Hibe(BNP256_B12P381_FIELD_ELEMENT_SIZE);
		int sizeOfFieldElement = hibeAlgorithm.getSizeOfFieldElement();
		int sizeOfG1Element = hibeAlgorithm.getSizeOfG1Element();
		int sizeOfG2Element = hibeAlgorithm.getSizeOfG2Element();
		int sizeOfCompressedGTElement = hibeAlgorithm.getSizeOfGTElement(true);
		int sizeOfGTElement = hibeAlgorithm.getSizeOfGTElement(false);
		System.out.println("Detecting elliptic curve..");
		detectEllipticCurve(sizeOfFieldElement, sizeOfG1Element);
		System.out.println();
		System.out.println("********************************");
		System.out.println("Size of Elements of the pairing curve:");
		System.out.println("Element of Z_p: " + sizeOfFieldElement + " Byte");
		System.out.println("Element of G1: " + sizeOfG1Element + " Byte");
		System.out.println("Element of G2: " + sizeOfG2Element + " Byte");
		System.out.println("Element of GT: " + sizeOfGTElement + " Byte");
		System.out.println("Element of GT (compressed): " + sizeOfCompressedGTElement + " Byte");
	}

	/**
	 * Detects the elliptic curve which is used by the HIBE. Prints the curve and
	 * sets the security level, accordingly.
	 * 
	 * @param sizeOfFieldElement
	 * @param sizeOfG1Element
	 * @return
	 */
	private static void detectEllipticCurve(int sizeOfFieldElement, int sizeOfG1Element) {
		switch (sizeOfFieldElement) {
		case BNP256_B12P381_FIELD_ELEMENT_SIZE:
			if (sizeOfG1Element == BNP256_G1_ELEMENT_SIZE) {
				curveidentifier = "BN-P256";
				System.out.println("Elliptic curve for pairings is BN-P256");
				System.out.println("Choosing algorithm set with theoretical symmetric equivalent strength: 100 Bit");
				securityLevel = 100;
				break;
			} else {
				if (sizeOfG1Element == B12P381_G1_ELEMENT_SIZE) {
					curveidentifier = "B12-P381";
					System.out.println("Elliptic curve for pairings is B12-P381");
					System.out
							.println("Choosing algorithm set with theoretical symmetric equivalent strength: 128 Bit");
					break;
				} else {
					curveidentifier = "Unknown";
					System.out.println("Elliptic curve for pairings is not known");
					System.out
							.println("Choosing algorithm set with theoretical symmetric equivalent strength: 128 Bit");
					break;
				}
			}
		case B12P455_FIELD_ELEMENT_SIZE:
			if (sizeOfG1Element == B12P455_G1_ELEMENT_SIZE) {
				curveidentifier = "B12-P455";
				System.out.println("Elliptic curve for pairings is B12-P455");
				System.out.println("Choosing algorithm set with theoretical symmetric equivalent strength: 128 Bit");
				break;
			}
		case BNP382_FIELD_ELEMENT_SIZE:
			if (sizeOfG1Element == BNP382_G1_ELEMENT_SIZE) {
				curveidentifier = "BN-P382";
				System.out.println("Elliptic curve for pairings is BN-P382");
				System.out.println("Choosing algorithm set with theoretical symmetric equivalent strength: 128 Bit");
				break;
			}
		default:
			curveidentifier = "Unknown";
			System.out.println("Elliptic curve for pairings is not known");
			System.out.println("Choosing algorithm set with theoretical symmetric equivalent strength: 128 Bit");
		}
	}
}
