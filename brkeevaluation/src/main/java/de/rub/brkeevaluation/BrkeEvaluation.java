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
	public static String curveidentifier;

	public static void main(String[] args) {
		System.out.println("Evaluation of AlgortihmSet1 of the BRKE instantiation");
		randomness = new SecureRandom();
		detectHibeSizes();

		System.out.println();
		System.out.println("Testing different communication sequences:");

		int iterations = 50;
		testLockStepCommunication(iterations);
		testAsynchWithoutCrossing(iterations);
		testAsynchWithCrossing(iterations);
		testWorstCase(iterations);
	}

	/**
	 * Test lock step communication
	 * 
	 * @param iterations - number of test iterations
	 */
	static void testLockStepCommunication(int iterations) {
		System.out.println();
		System.out.println("********************************");
		System.out.println("Test Case 1: Lockstep communication");
		System.out.println("********************************");
		System.out.println("Communication sequence:");
		System.out.println("Sender  -> Receiver ; generated Ciphertext");
		System.out.println("A(0) -> B(1); Ciphertext 0");
		System.out.println("B(2) -> A(3); Ciphertext 1");
		System.out.println("Jump to 0.");
		System.out.println("Repeat: " + iterations + " times.");
		System.out.println("Every message is directly received.");

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
		try {
			BufferedWriter writer = new BufferedWriter(new FileWriter(curveidentifier + "_LockStep_fulldata.csv"));
			String content = "Iteration;Step 0;Step 1;Step 2;Step 3;kuKemCiphertext size 0;kuKemCiphertext size 1;UserstateA size;UserstateB size";
			writer.append(content);
			writer.newLine();
			writer.close();

		} catch (IOException e) {
			e.printStackTrace();
		}
		/**
		 * Naming is corresponding to communication sequence numbers
		 */
		int communicationsteps = 4;
		int numberOfCiphertexts = 2;
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

		BrkeSendOutput sendOutputA;
		BrkeSendOutput sendOutputB;
		BrkeSymmetricKey sessionKeyA;
		BrkeSymmetricKey sessionKeyB;

		BrkeCiphertext ciphertext[] = new BrkeCiphertext[numberOfCiphertexts];
		long kukemCiphertextSize[][] = new long[numberOfCiphertexts][iterations + 1];

		System.out.println("Userstate A size before communication: " + GraphLayout.parseInstance(brkeUserA).totalSize()
				+ " byte.");
		System.out.println("Userstate B size before communication: " + GraphLayout.parseInstance(brkeUserB).totalSize()
				+ " byte.");

		/**
		 * Do one more iteration, because first communication round is always different.
		 * We save the data of the first iteration in the files, but do not consider
		 * them when computing the average.
		 */
		for (int i = 0; i < iterations + 1; i++) {
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
				for (int j = 0; j < communicationsteps; j++) {
					sumTime[j] = sumTime[j] + ((endTime[j] - startTime[j]) / 1000000);
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
				for (int j = 0; j < communicationsteps; j++) {
					output += ((endTime[j] - startTime[j]) / 1000000) + ";";
				}
				for (int j = 0; j < numberOfCiphertexts; j++) {
					output += kukemCiphertextSize[j][i] + ";";
				}
				for (int j = 0; j < communicationsteps; j++) {
					output += (endSize[j] - startSize[j]) + ";";
				}
				writer.append(output);
				writer.newLine();
				writer.close();
			} catch (IOException e) {
			}
		}
		/**
		 * Print results to console.
		 */
		System.out.println();
		System.out.println("********************************");
		System.out.println("Average duration:");
		System.out
				.println("Communication step 0 - A sends    - takes: " + (sumTime[0] / iterations) + " ms on average.");
		System.out
				.println("Communication step 1 - B receives - takes: " + (sumTime[1] / iterations) + " ms on average.");
		System.out
				.println("Communication step 2 - B sends    - takes: " + (sumTime[2] / iterations) + " ms on average.");
		System.out
				.println("Communication step 3 - A receives - takes: " + (sumTime[3] / iterations) + " ms on average.");

		System.out.println("********************************");
		System.out.println("Average size change:");
		System.out.println("Communication step 0 - A sends    - changes the state by: " + (sumSize[0] / iterations)
				+ " byte on average.");
		System.out.println("Communication step 1 - B receives - changes the state by: " + (sumSize[1] / iterations)
				+ " byte on average.");
		System.out.println("Communication step 2 - B sends    - changes the state by: " + (sumSize[2] / iterations)
				+ " byte on average.");
		System.out.println("Communication step 3 - A receives - changes the state by: " + (sumSize[3] / iterations)
				+ " byte on average.");

		long auxilaryKuKemCiphertextSize[] = new long[numberOfCiphertexts];
		boolean constantCiphertext[] = new boolean[numberOfCiphertexts];

		long baseCiphertextSize = GraphLayout.parseInstance(ciphertext[0]).totalSize()
				- kukemCiphertextSize[0][iterations];
		System.out.println();
		System.out.println("********************************");
		System.out.println("Size of ciphertexts:");
		System.out.println("Base ciphertext size (without kuKem ciphertext): " + baseCiphertextSize);
		System.out.println("Individual ciphertext parts have size:");
		printBaseCiphertextSizes(ciphertext[0]);
		/**
		 * Check if KuKem ciphertext sizes are constant
		 */
		for (int i = 0; i < numberOfCiphertexts; i++) {
			auxilaryKuKemCiphertextSize[i] = kukemCiphertextSize[i][1];
			constantCiphertext[i] = true;
		}
		for (int i = 2; i < iterations; i++) {
			for (int j = 0; j < numberOfCiphertexts; j++) {
				if (auxilaryKuKemCiphertextSize[j] != kukemCiphertextSize[j][i]) {
					constantCiphertext[j] = false;
				}
			}
		}
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

	/**
	 * Test asynchronous communication without crossing messages.
	 * 
	 * @param iterations - number of test iterations
	 */
	private static void testAsynchWithoutCrossing(int iterations) {
		System.out.println();
		System.out.println("********************************");
		System.out.println("Test Case 2: Asynchronous communication without crossing messages");
		System.out.println("********************************");
		System.out.println("Communication sequence:");
		System.out.println("Sender  -> Receiver ; generated Ciphertext");
		System.out.println("A(0) -> B(1); Ciphertext 0");
		System.out.println("A(2) -> B(3); Ciphertext 1");
		System.out.println("A(4) -> B(5); Ciphertext 2");
		System.out.println("B(6) -> A(7); Ciphertext 3");
		System.out.println("B(8) -> A(9); Ciphertext 4");
		System.out.println("Jump to 0.");
		System.out.println("Repeat: " + iterations + " times.");
		System.out.println("Every message is directly received.");

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
		 * Reset file
		 */
		try {
			BufferedWriter writer = new BufferedWriter(new FileWriter(curveidentifier + "_AsynchWoCross_fulldata.csv"));
			String content = "Iteration;Step 0;Step 1;Step 2;Step 3;Step 4;Step 5;Step 6;Step 7;Step 8;Step 9;kuKemCiphertext size 0;kuKemCiphertext size 1;kuKemCiphertext size 2;kuKemCiphertext size 3;kuKemCiphertext size 4;Userstate diff 0;Userstate diff 1;Userstate diff 2;Userstate diff 3;Userstate diff 4;Userstate diff 5;Userstate diff 6;Userstate diff 7;Userstate diff 8;Userstate diff 9";
			writer.append(content);
			writer.newLine();
			writer.close();

		} catch (IOException e) {
		}
		/**
		 * Naming is corresponding to communication sequence numbers
		 */
		int communicationsteps = 10;
		int numberOfCiphertexts = 5;
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

		BrkeSendOutput sendOutputA[] = new BrkeSendOutput[3];
		BrkeSendOutput sendOutputB[] = new BrkeSendOutput[2];

		BrkeSymmetricKey sessionKeyA[] = new BrkeSymmetricKey[2];
		BrkeSymmetricKey sessionKeyB[] = new BrkeSymmetricKey[3];

		BrkeCiphertext ciphertext[] = new BrkeCiphertext[numberOfCiphertexts];
		long kukemCiphertextSize[][] = new long[numberOfCiphertexts][iterations + 1];

		System.out.println("Userstate A size before communication: " + GraphLayout.parseInstance(brkeUserA).totalSize()
				+ " byte.");
		System.out.println("Userstate B size before communication: " + GraphLayout.parseInstance(brkeUserB).totalSize()
				+ " byte.");

		for (int i = 0; i < iterations + 1; i++) {
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
			for (int j = 0; j < numberOfCiphertexts; j++) {
				kukemCiphertextSize[j][i] = getKuKemCiphertextSize(ciphertext[j]);
			}

			/**
			 * Sum of the measurements
			 */
			if (i != 0) {
				/**
				 * Sum of the measurements
				 */
				for (int j = 0; j < communicationsteps; j++) {
					sumTime[j] = sumTime[j] + ((endTime[j] - startTime[j]) / 1000000);
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
				for (int j = 0; j < communicationsteps; j++) {
					output += ((endTime[j] - startTime[j]) / 1000000) + ";";
				}
				for (int j = 0; j < numberOfCiphertexts; j++) {
					output += kukemCiphertextSize[j][i] + ";";
				}
				for (int j = 0; j < communicationsteps; j++) {
					output += (endSize[j] - startSize[j]) + ";";
				}
				writer.append(output);
				writer.newLine();
				writer.close();
			} catch (IOException e) {
			}
		}
		/**
		 * Print results to console.
		 */
		/**
		 * Print timings
		 */
		System.out.println();
		System.out.println("********************************");
		System.out.println("Average duration:");
		System.out
				.println("Communication step 0 - A sends    - takes: " + (sumTime[0] / iterations) + " ms on average.");
		System.out
				.println("Communication step 1 - B receives - takes: " + (sumTime[1] / iterations) + " ms on average.");
		System.out
				.println("Communication step 2 - A sends    - takes: " + (sumTime[2] / iterations) + " ms on average.");
		System.out
				.println("Communication step 3 - B receives - takes: " + (sumTime[3] / iterations) + " ms on average.");
		System.out
				.println("Communication step 4 - A sends    - takes: " + (sumTime[4] / iterations) + " ms on average.");
		System.out
				.println("Communication step 5 - B receives - takes: " + (sumTime[5] / iterations) + " ms on average.");
		System.out
				.println("Communication step 6 - B sends    - takes: " + (sumTime[6] / iterations) + " ms on average.");
		System.out
				.println("Communication step 7 - A receives - takes: " + (sumTime[7] / iterations) + " ms on average.");
		System.out
				.println("Communication step 8 - B sends    - takes: " + (sumTime[8] / iterations) + " ms on average.");
		System.out
				.println("Communication step 9 - A receives - takes: " + (sumTime[9] / iterations) + " ms on average.");

		System.out.println("********************************");
		System.out.println("Average size change:");
		System.out.println("Communication step 0 - A sends    - changes the state by: " + (sumSize[0] / iterations)
				+ " byte on average.");
		System.out.println("Communication step 1 - B receives - changes the state by: " + (sumSize[1] / iterations)
				+ " byte on average.");
		System.out.println("Communication step 2 - A sends    - changes the state by: " + (sumSize[2] / iterations)
				+ " byte on average.");
		System.out.println("Communication step 3 - B receives - changes the state by: " + (sumSize[3] / iterations)
				+ " byte on average.");
		System.out.println("Communication step 4 - A sends    - changes the state by: " + (sumSize[4] / iterations)
				+ " byte on average.");
		System.out.println("Communication step 5 - B receives - changes the state by: " + (sumSize[5] / iterations)
				+ " byte on average.");
		System.out.println("Communication step 6 - B sends    - changes the state by: " + (sumSize[6] / iterations)
				+ " byte on average.");
		System.out.println("Communication step 7 - A receives - changes the state by: " + (sumSize[7] / iterations)
				+ " byte on average.");
		System.out.println("Communication step 8 - B sends    - changes the state by: " + (sumSize[8] / iterations)
				+ " byte on average.");
		System.out.println("Communication step 9 - A receives - changes the state by: " + (sumSize[9] / iterations)
				+ " byte on average.");

		long auxilaryKuKemCiphertextSize[] = new long[numberOfCiphertexts];
		boolean constantCiphertext[] = new boolean[numberOfCiphertexts];

		long baseCiphertextSize = GraphLayout.parseInstance(ciphertext[0]).totalSize()
				- kukemCiphertextSize[0][iterations];
		System.out.println();
		System.out.println("********************************");
		System.out.println("Size of ciphertexts:");
		System.out.println("Base ciphertext size (without kuKem ciphertext): " + baseCiphertextSize);
		System.out.println("Individual ciphertext parts have size:");
		printBaseCiphertextSizes(ciphertext[0]);
		/**
		 * Check if KuKem ciphertext sizes are constant
		 */
		for (int i = 0; i < numberOfCiphertexts; i++) {
			auxilaryKuKemCiphertextSize[i] = kukemCiphertextSize[i][1];
			constantCiphertext[i] = true;
		}
		for (int i = 2; i < iterations; i++) {
			for (int j = 0; j < numberOfCiphertexts; j++) {
				if (auxilaryKuKemCiphertextSize[j] != kukemCiphertextSize[j][i]) {
					constantCiphertext[j] = false;
				}
			}
		}
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

	/**
	 * Test asynchronous communication with crossing messages.
	 * 
	 * @param iterations - number of test iterations
	 */
	private static void testAsynchWithCrossing(int iterations) {
		System.out.println();
		System.out.println("********************************");
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
		System.out.println("Jump to 0.");
		System.out.println("Repeat: " + iterations + " times.");
		System.out.println("Messages cross while communicating.");

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
		 * Reset file
		 */
		try {
			BufferedWriter writer = new BufferedWriter(
					new FileWriter(curveidentifier + "_AsynchWithCross_fulldata.csv"));
			String content = "Iteration;Step 0;Step 1;Step 2;Step 3;Step 4;Step 5;Step 6;Step 7;Step 8;Step 9;kuKemCiphertext size 0;kuKemCiphertext size 1;kuKemCiphertext size 2;kuKemCiphertext size 3;kuKemCiphertext size 4;Userstate diff 0;Userstate diff 1;Userstate diff 2;Userstate diff 3;Userstate diff 4;Userstate diff 5;Userstate diff 6;Userstate diff 7;Userstate diff 8;Userstate diff 9";
			writer.append(content);
			writer.newLine();
			writer.close();

		} catch (IOException e) {
		}
		/**
		 * Naming is corresponding to communication sequence numbers
		 */
		int communicationsteps = 10;
		int numberOfCiphertexts = 5;
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

		BrkeSendOutput sendOutputA[] = new BrkeSendOutput[3];
		BrkeSendOutput sendOutputB[] = new BrkeSendOutput[2];

		BrkeSymmetricKey sessionKeyA[] = new BrkeSymmetricKey[2];
		BrkeSymmetricKey sessionKeyB[] = new BrkeSymmetricKey[3];

		BrkeCiphertext ciphertext[] = new BrkeCiphertext[numberOfCiphertexts];
		long kukemCiphertextSize[][] = new long[numberOfCiphertexts][iterations + 1];

		System.out.println("Userstate A size before communication: " + GraphLayout.parseInstance(brkeUserA).totalSize()
				+ " byte.");
		System.out.println("Userstate B size before communication: " + GraphLayout.parseInstance(brkeUserB).totalSize()
				+ " byte.");

		for (int i = 0; i < iterations + 1; i++) {
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
			for (int j = 0; j < numberOfCiphertexts; j++) {
				kukemCiphertextSize[j][i] = getKuKemCiphertextSize(ciphertext[j]);
			}

			/**
			 * Sum of the measurements
			 */
			if (i != 0) {
				for (int j = 0; j < communicationsteps; j++) {
					sumTime[j] = sumTime[j] + ((endTime[j] - startTime[j]) / 1000000);
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
				for (int j = 0; j < communicationsteps; j++) {
					output += ((endTime[j] - startTime[j]) / 1000000) + ";";
				}
				for (int j = 0; j < numberOfCiphertexts; j++) {
					output += kukemCiphertextSize[j][i] + ";";
				}
				for (int j = 0; j < communicationsteps; j++) {
					output += (endSize[j] - startSize[j]) + ";";
				}
				writer.append(output);
				writer.newLine();
				writer.close();
			} catch (IOException e) {
			}
		}
		/**
		 * Print results to console.
		 */
		/**
		 * Print timings
		 */
		System.out.println();
		System.out.println("********************************");
		System.out.println("Average duration:");
		System.out
				.println("Communication step 0 - A sends    - takes: " + (sumTime[0] / iterations) + " ms on average.");
		System.out
				.println("Communication step 1 - A sends    - takes: " + (sumTime[1] / iterations) + " ms on average.");
		System.out
				.println("Communication step 2 - B sends    - takes: " + (sumTime[2] / iterations) + " ms on average.");
		System.out
				.println("Communication step 3 - B sends    - takes: " + (sumTime[3] / iterations) + " ms on average.");
		System.out
				.println("Communication step 4 - A receives - takes: " + (sumTime[4] / iterations) + " ms on average.");
		System.out
				.println("Communication step 5 - A sends    - takes: " + (sumTime[5] / iterations) + " ms on average.");
		System.out
				.println("Communication step 6 - B receives - takes: " + (sumTime[6] / iterations) + " ms on average.");
		System.out
				.println("Communication step 7 - B receives - takes: " + (sumTime[7] / iterations) + " ms on average.");
		System.out
				.println("Communication step 8 - B receives - takes: " + (sumTime[8] / iterations) + " ms on average.");
		System.out
				.println("Communication step 9 - A receives - takes: " + (sumTime[9] / iterations) + " ms on average.");

		System.out.println("********************************");
		System.out.println("Average size change:");
		System.out.println("Communication step 0 - A sends    - changes the state by: " + (sumSize[0] / iterations)
				+ " byte on average.");
		System.out.println("Communication step 1 - A sends    - changes the state by: " + (sumSize[1] / iterations)
				+ " byte on average.");
		System.out.println("Communication step 2 - B sends    - changes the state by: " + (sumSize[2] / iterations)
				+ " byte on average.");
		System.out.println("Communication step 3 - B sends    - changes the state by: " + (sumSize[3] / iterations)
				+ " byte on average.");
		System.out.println("Communication step 4 - A receives - changes the state by: " + (sumSize[4] / iterations)
				+ " byte on average.");
		System.out.println("Communication step 5 - B sends    - changes the state by: " + (sumSize[5] / iterations)
				+ " byte on average.");
		System.out.println("Communication step 6 - B receives - changes the state by: " + (sumSize[6] / iterations)
				+ " byte on average.");
		System.out.println("Communication step 7 - B receives - changes the state by: " + (sumSize[7] / iterations)
				+ " byte on average.");
		System.out.println("Communication step 8 - B receives - changes the state by: " + (sumSize[8] / iterations)
				+ " byte on average.");
		System.out.println("Communication step 9 - A receives - changes the state by: " + (sumSize[9] / iterations)
				+ " byte on average.");

		long auxilaryKuKemCiphertextSize[] = new long[numberOfCiphertexts];
		boolean constantCiphertext[] = new boolean[numberOfCiphertexts];

		long baseCiphertextSize = GraphLayout.parseInstance(ciphertext[0]).totalSize()
				- kukemCiphertextSize[0][iterations];
		System.out.println();
		System.out.println("********************************");
		System.out.println("Size of ciphertexts:");
		System.out.println("Base ciphertext size (without kuKem ciphertext): " + baseCiphertextSize);
		System.out.println("Individual ciphertext parts have size:");
		printBaseCiphertextSizes(ciphertext[0]);
		/**
		 * Check if KuKem ciphertext sizes are constant
		 */
		for (int i = 0; i < numberOfCiphertexts; i++) {
			auxilaryKuKemCiphertextSize[i] = kukemCiphertextSize[i][1];
			constantCiphertext[i] = true;
		}
		for (int i = 2; i < iterations; i++) {
			for (int j = 0; j < numberOfCiphertexts; j++) {
				if (auxilaryKuKemCiphertextSize[j] != kukemCiphertextSize[j][i]) {
					constantCiphertext[j] = false;
				}
			}
		}
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

	/**
	 * Test "worst case" communication.
	 * 
	 * @param iterations - number of test iterations
	 */
	private static void testWorstCase(int iterations) {
		System.out.println();
		System.out.println("********************************");
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
		System.out.println("Jump to 0.");
		System.out.println("Repeat: " + iterations + " times.");
		System.out.println("Messages cross while communicating.");

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
		 * Reset file
		 */
		try {
			BufferedWriter writer = new BufferedWriter(new FileWriter(curveidentifier + "_WorstCase_fulldata.csv"));
			String content = "Iteration;Step 0;Step 1;Step 2;Step 3;Step 4;Step 5;Step 6;Step 7;Step 8;Step 9;Step 10;Step 11;Step 12;Step 13;Step 14;Step 15;kuKemCiphertext size 0;kuKemCiphertext size 1;kuKemCiphertext size 2;kuKemCiphertext size 3;kuKemCiphertext size 4;kuKemCiphertext size 5;kuKemCiphertext size 6;kuKemCiphertext size 7;Userstate diff 0;Userstate diff 1;Userstate diff 2;Userstate diff 3;Userstate diff 4;Userstate diff 5;Userstate diff 6;Userstate diff 7;Userstate diff 8;Userstate diff 9";
			writer.append(content);
			writer.newLine();
			writer.close();

		} catch (IOException e) {
		}
		/**
		 * Naming is corresponding to communication sequence numbers
		 */
		int communicationsteps = 16;
		int numberOfCiphertexts = 8;
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

		BrkeSendOutput sendOutputA[] = new BrkeSendOutput[6];
		BrkeSendOutput sendOutputB[] = new BrkeSendOutput[2];

		BrkeSymmetricKey sessionKeyA[] = new BrkeSymmetricKey[2];
		BrkeSymmetricKey sessionKeyB[] = new BrkeSymmetricKey[6];

		BrkeCiphertext ciphertext[] = new BrkeCiphertext[numberOfCiphertexts];
		long kukemCiphertextSize[][] = new long[numberOfCiphertexts][iterations + 1];

		System.out.println("Userstate A size before communication: " + GraphLayout.parseInstance(brkeUserA).totalSize()
				+ " byte.");
		System.out.println("Userstate B size before communication: " + GraphLayout.parseInstance(brkeUserB).totalSize()
				+ " byte.");

		for (int i = 0; i < iterations + 1; i++) {
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
			for (int j = 0; j < numberOfCiphertexts; j++) {
				kukemCiphertextSize[j][i] = getKuKemCiphertextSize(ciphertext[j]);
			}

			/**
			 * Sum of the measurements
			 */
			if (i != 0) {
				/**
				 * Sum of the measurements
				 */
				for (int j = 0; j < communicationsteps; j++) {
					sumTime[j] = sumTime[j] + ((endTime[j] - startTime[j]) / 1000000);
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
				for (int j = 0; j < communicationsteps; j++) {
					output += ((endTime[j] - startTime[j]) / 1000000) + ";";
				}
				for (int j = 0; j < numberOfCiphertexts; j++) {
					output += kukemCiphertextSize[j][i] + ";";
				}
				for (int j = 0; j < communicationsteps; j++) {
					output += (endSize[j] - startSize[j]) + ";";
				}
				writer.append(output);
				writer.newLine();
				writer.close();
			} catch (IOException e) {
			}
		}
		/**
		 * Print results to console.
		 */
		/**
		 * Print timings
		 */
		System.out.println();
		System.out.println("********************************");
		System.out.println("Average duration:");
		System.out
				.println("Communication step 0 - A sends    - takes: " + (sumTime[0] / iterations) + " ms on average.");
		System.out
				.println("Communication step 1 - A sends    - takes: " + (sumTime[1] / iterations) + " ms on average.");
		System.out
				.println("Communication step 2 - A sends    - takes: " + (sumTime[2] / iterations) + " ms on average.");
		System.out
				.println("Communication step 3 - A sends    - takes: " + (sumTime[3] / iterations) + " ms on average.");
		System.out
				.println("Communication step 4 - A sends    - takes: " + (sumTime[4] / iterations) + " ms on average.");
		System.out
				.println("Communication step 5 - B sends    - takes: " + (sumTime[5] / iterations) + " ms on average.");
		System.out
				.println("Communication step 6 - A receives - takes: " + (sumTime[6] / iterations) + " ms on average.");
		System.out
				.println("Communication step 7 - B sends    - takes: " + (sumTime[7] / iterations) + " ms on average.");
		System.out
				.println("Communication step 8 - A receives - takes: " + (sumTime[8] / iterations) + " ms on average.");
		System.out
				.println("Communication step 9 - A sends    - takes: " + (sumTime[9] / iterations) + " ms on average.");
		for (int i = 10; i < 16; i++) {
			System.out.println("Communication step " + i + " - B receives - takes: " + (sumTime[i] / iterations)
					+ " ms on average.");
		}

		System.out.println("********************************");
		System.out.println("Average size change:");
		System.out.println("Communication step 0 - A sends    - changes the state by: " + (sumSize[0] / iterations)
				+ " byte on average.");
		System.out.println("Communication step 1 - A sends    - changes the state by: " + (sumSize[1] / iterations)
				+ " byte on average.");
		System.out.println("Communication step 2 - A sends    - changes the state by: " + (sumSize[2] / iterations)
				+ " byte on average.");
		System.out.println("Communication step 3 - A sends    - changes the state by: " + (sumSize[3] / iterations)
				+ " byte on average.");
		System.out.println("Communication step 4 - A sends    - changes the state by: " + (sumSize[4] / iterations)
				+ " byte on average.");
		System.out.println("Communication step 5 - B sends    - changes the state by: " + (sumSize[5] / iterations)
				+ " byte on average.");
		System.out.println("Communication step 6 - A receives - changes the state by: " + (sumSize[6] / iterations)
				+ " byte on average.");
		System.out.println("Communication step 7 - B sends    - changes the state by: " + (sumSize[7] / iterations)
				+ " byte on average.");
		System.out.println("Communication step 8 - A receives - changes the state by: " + (sumSize[8] / iterations)
				+ " byte on average.");
		System.out.println("Communication step 9 - A sends    - changes the state by: " + (sumSize[9] / iterations)
				+ " byte on average.");
		for (int i = 10; i < 16; i++) {
			System.out.println("Communication step " + i + " - B receives - changes the state by: "
					+ (sumSize[i] / iterations) + " byte on average.");
		}
		long auxilaryKuKemCiphertextSize[] = new long[numberOfCiphertexts];
		boolean constantCiphertext[] = new boolean[numberOfCiphertexts];

		long baseCiphertextSize = GraphLayout.parseInstance(ciphertext[0]).totalSize()
				- kukemCiphertextSize[0][iterations];
		System.out.println();
		System.out.println("********************************");
		System.out.println("Size of ciphertexts:");
		System.out.println("Base ciphertext size (without kuKem ciphertext): " + baseCiphertextSize);
		System.out.println("Individual ciphertext parts have size:");
		printBaseCiphertextSizes(ciphertext[0]);
		/**
		 * Check if KuKem ciphertext sizes are constant
		 */
		for (int i = 0; i < numberOfCiphertexts; i++) {
			auxilaryKuKemCiphertextSize[i] = kukemCiphertextSize[i][1];
			constantCiphertext[i] = true;
		}
		for (int i = 2; i < iterations; i++) {
			for (int j = 0; j < numberOfCiphertexts; j++) {
				if (auxilaryKuKemCiphertextSize[j] != kukemCiphertextSize[j][i]) {
					constantCiphertext[j] = false;
				}
			}
		}
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

	/**
	 * Get the size of the KuKem ciphertext.
	 * 
	 * @param ciphertext
	 * @return
	 */
	private static long getKuKemCiphertextSize(BrkeCiphertext ciphertext) {
		QueuedKuKemCiphertext queuedKuKemCiphertext = ciphertext.getCiphertext();
		if (queuedKuKemCiphertext.getKuKemCiphertexts() == null) {
			return 0;
		} else {
			return GraphLayout.parseInstance(queuedKuKemCiphertext.getKuKemCiphertexts()).totalSize();
		}
	}

	/**
	 * Print sizes of the base Brke ciphertext (without kuKem ciphertexts) to the
	 * console.
	 * 
	 * @param ciphertext
	 */
	private static void printBaseCiphertextSizes(BrkeCiphertext ciphertext) {
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

	/**
	 * Detects the sizes of the HIBE and prints them to console.
	 */
	private static void detectHibeSizes() {
		/**
		 * Get the size of the elements of the elliptic curve used in the HIBE. Detect
		 * the elliptic curve and get the security level. Print the element sizes to the
		 * console.
		 */
		Hibe hibeAlgorithm = new Hibe(32);
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
		case 32:
			if (sizeOfG1Element == 33) {
				curveidentifier = "BN-P256";
				System.out.println("Elliptic curve for pairings is BN-P256");
				System.out.println("Choosing algorithm set with theoretical symmetric equivalent strength: 100 Bit");
				securityLevel = 100;
				break;
			} else {
				if (sizeOfG1Element == 49) {
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
		case 38:
			if (sizeOfG1Element == 58) {
				curveidentifier = "B12-P455";
				System.out.println("Elliptic curve for pairings is B12-P455");
				System.out.println("Choosing algorithm set with theoretical symmetric equivalent strength: 128 Bit");
				break;
			}
		case 48:
			if (sizeOfG1Element == 49) {
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
