package de.rub.rkeinstantiation.utility;

import java.util.LinkedList;
import java.util.Queue;

import org.bouncycastle.crypto.digests.SHA512Digest;

import de.rub.rke.brke.BrkeCiphertext;
import de.rub.rke.kukem.KuKemCiphertext;
import de.rub.rke.kukem.KuKemPublicKey;
import de.rub.rke.queuedkukem.QueuedKuKemCiphertext;
import de.rub.rke.signature.SignatureVerificationKey;
import de.rub.rke.variables.AssociatedData;
import de.rub.rkeinstantiation.brkekem.ECIESKemCiphertext;
import de.rub.rkeinstantiation.brkekukem.BrkeKuKemCiphertext;
import de.rub.rkeinstantiation.brkekukem.BrkeKuKemPublicKey;
import de.rub.rkeinstantiation.brkesignature.DLPChameleonSignatureOutput;
import de.rub.rkeinstantiation.brkesignature.DLPChameleonVerificationKey;
import de.rub.rkeinstantiation.hibewrapper.HibeCiphertext;
import de.rub.rkeinstantiation.variables.BrkeAssociatedData;

/**
 * Utility class that hashes a BrkeCiphertext|AssociatedData (for AlgorithmSet1)
 * Pair with SHA512. One functions hashes a complete BrkeCiphertext(including
 * the Signature), and one function hashes all parts (excluding the signature)
 * for Signing.
 * 
 * @author Marco Smeets
 *
 */
public class CiphertextEncoder {

	/**
	 * Hashes an Ad|Ciphertext pair with SHA512.
	 * 
	 * @param ad
	 * @param ciphertext
	 * @return
	 */
	public static byte[] hashAdCiphertext(AssociatedData ad, BrkeCiphertext ciphertext) {
		SHA512Digest hash = new SHA512Digest();
		byte[] output = new byte[hash.getDigestSize()];

		byte associatedData[] = ((BrkeAssociatedData) ad).getAsBytes();
		BrkeKuKemPublicKey kuKemPublicKey = (BrkeKuKemPublicKey) ciphertext.getPublicKey();
		DLPChameleonVerificationKey verificationKey = (DLPChameleonVerificationKey) ciphertext.getVerificationKey();
		QueuedKuKemCiphertext queuedKuKemCiphertext = ciphertext.getCiphertext();
		ECIESKemCiphertext kemCiphertext = (ECIESKemCiphertext) queuedKuKemCiphertext.getKemCiphertext();
		DLPChameleonSignatureOutput signatureOutput = (DLPChameleonSignatureOutput) ciphertext.getSignature();
		if (ciphertext.getNumberOfUsedKeys() > 1) {
			Queue<KuKemCiphertext> kuKemCiphertexts = new LinkedList<KuKemCiphertext>(
					queuedKuKemCiphertext.getKuKemCiphertexts());

			/**
			 * Process AssociatedData
			 */
			hash.update(associatedData, 0, associatedData.length);

			/**
			 * Process numberOfReceivedMessages
			 */
			hash.update((byte) ciphertext.getNumberOfReceivedMessages());

			/**
			 * Process BrkeKuKemPublicKey
			 */
			hash.update(kuKemPublicKey.getHibePublicParameter().getEncapsulationPublicParameter(), 0,
					kuKemPublicKey.getHibePublicParameter().getEncapsulationPublicParameter().length);
			hash.update(kuKemPublicKey.getHibePublicParameter().getEncodedPublicParameter(), 0,
					kuKemPublicKey.getHibePublicParameter().getEncodedPublicParameter().length);
			hash.update(kuKemPublicKey.getIdentityInformation(), 0, kuKemPublicKey.getIdentityInformation().length);
			hash.update((byte) kuKemPublicKey.getLevel());

			/**
			 * Process Signature Verification Key
			 */
			byte[] encodedBigInteger;
			encodedBigInteger = verificationKey.getG1().toByteArray();
			hash.update(encodedBigInteger, 0, encodedBigInteger.length);
			encodedBigInteger = verificationKey.getG2().toByteArray();
			hash.update(encodedBigInteger, 0, encodedBigInteger.length);
			encodedBigInteger = verificationKey.getG3().toByteArray();
			hash.update(encodedBigInteger, 0, encodedBigInteger.length);
			hash.update(verificationKey.getZ0(), 0, verificationKey.getZ0().length);

			/**
			 * Process number of used Keys
			 */
			hash.update((byte) ciphertext.getNumberOfUsedKeys());

			/**
			 * Process queued KuKem ciphertext
			 */
			hash.update(kemCiphertext.getCiphertext(), 0, kemCiphertext.getCiphertext().length);
			while (!kuKemCiphertexts.isEmpty()) {
				BrkeKuKemCiphertext currentCiphertext = (BrkeKuKemCiphertext) kuKemCiphertexts.remove();
				HibeCiphertext hibeCiphertext = currentCiphertext.getCiphertext();
				hash.update(hibeCiphertext.getCom(), 0, hibeCiphertext.getCom().length);
				hash.update(hibeCiphertext.getCiphertext(), 0, hibeCiphertext.getCiphertext().length);
				hash.update(hibeCiphertext.getMacTag(), 0, hibeCiphertext.getMacTag().length);
			}

			/**
			 * Process Signature
			 */
			encodedBigInteger = signatureOutput.getSign0().toByteArray();
			hash.update(encodedBigInteger, 0, encodedBigInteger.length);
			encodedBigInteger = signatureOutput.getSign1().toByteArray();
			hash.update(encodedBigInteger, 0, encodedBigInteger.length);
		} else {
			/**
			 * Process AssociatedData
			 */
			hash.update(associatedData, 0, associatedData.length);

			/**
			 * Process numberOfReceivedMessages
			 */
			hash.update((byte) ciphertext.getNumberOfReceivedMessages());

			/**
			 * Process BrkeKuKemPublicKey
			 */
			hash.update(kuKemPublicKey.getHibePublicParameter().getEncapsulationPublicParameter(), 0,
					kuKemPublicKey.getHibePublicParameter().getEncapsulationPublicParameter().length);
			hash.update(kuKemPublicKey.getHibePublicParameter().getEncodedPublicParameter(), 0,
					kuKemPublicKey.getHibePublicParameter().getEncodedPublicParameter().length);
			hash.update(kuKemPublicKey.getIdentityInformation(), 0, kuKemPublicKey.getIdentityInformation().length);
			hash.update((byte) kuKemPublicKey.getLevel());

			/**
			 * Process Signature Verification Key
			 */
			byte[] encodedBigInteger;
			encodedBigInteger = verificationKey.getG1().toByteArray();
			hash.update(encodedBigInteger, 0, encodedBigInteger.length);
			encodedBigInteger = verificationKey.getG2().toByteArray();
			hash.update(encodedBigInteger, 0, encodedBigInteger.length);
			encodedBigInteger = verificationKey.getG3().toByteArray();
			hash.update(encodedBigInteger, 0, encodedBigInteger.length);
			hash.update(verificationKey.getZ0(), 0, verificationKey.getZ0().length);

			/**
			 * Process number of used Keys
			 */
			hash.update((byte) ciphertext.getNumberOfUsedKeys());

			/**
			 * Process queued KuKem ciphertext
			 */
			hash.update(kemCiphertext.getCiphertext(), 0, kemCiphertext.getCiphertext().length);

			/**
			 * Process Signature
			 */
			encodedBigInteger = signatureOutput.getSign0().toByteArray();
			hash.update(encodedBigInteger, 0, encodedBigInteger.length);
			encodedBigInteger = signatureOutput.getSign1().toByteArray();
			hash.update(encodedBigInteger, 0, encodedBigInteger.length);
		}
		hash.doFinal(output, 0);
		return output;
	}

	/**
	 * Hashes Ad|(All ciphertext parts) for signing with SHA512.
	 * 
	 * @param ad
	 * @param numberOfReceivedMessages
	 * @param publicKey
	 * @param verificationKey
	 * @param numberOfUsedKeys
	 * @param queuedKuKemCiphertext
	 * @return
	 */
	public static byte[] hashAdCiphertextPartsForSigning(AssociatedData ad, int numberOfReceivedMessages,
			KuKemPublicKey publicKey, SignatureVerificationKey verificationKey, int numberOfUsedKeys,
			QueuedKuKemCiphertext queuedKuKemCiphertext) {
		SHA512Digest hash = new SHA512Digest();
		byte[] output = new byte[hash.getDigestSize()];

		byte associatedData[] = ((BrkeAssociatedData) ad).getAsBytes();
		BrkeKuKemPublicKey kuKemPublicKey = (BrkeKuKemPublicKey) publicKey;
		DLPChameleonVerificationKey dlpVerificationKey = (DLPChameleonVerificationKey) verificationKey;
		ECIESKemCiphertext kemCiphertext = (ECIESKemCiphertext) queuedKuKemCiphertext.getKemCiphertext();
		if (numberOfUsedKeys > 1) {
			Queue<KuKemCiphertext> kuKemCiphertexts = new LinkedList<KuKemCiphertext>(
					queuedKuKemCiphertext.getKuKemCiphertexts());

			/**
			 * Process AssociatedData
			 */
			hash.update(associatedData, 0, associatedData.length);

			/**
			 * Process numberOfReceivedMessages
			 */
			hash.update((byte) numberOfReceivedMessages);

			/**
			 * Process BrkeKuKemPublicKey
			 */
			hash.update(kuKemPublicKey.getHibePublicParameter().getEncapsulationPublicParameter(), 0,
					kuKemPublicKey.getHibePublicParameter().getEncapsulationPublicParameter().length);
			hash.update(kuKemPublicKey.getHibePublicParameter().getEncodedPublicParameter(), 0,
					kuKemPublicKey.getHibePublicParameter().getEncodedPublicParameter().length);
			hash.update(kuKemPublicKey.getIdentityInformation(), 0, kuKemPublicKey.getIdentityInformation().length);
			hash.update((byte) kuKemPublicKey.getLevel());

			/**
			 * Process Signature Verification Key
			 */
			byte[] encodedBigInteger;
			encodedBigInteger = dlpVerificationKey.getG1().toByteArray();
			hash.update(encodedBigInteger, 0, encodedBigInteger.length);
			encodedBigInteger = dlpVerificationKey.getG2().toByteArray();
			hash.update(encodedBigInteger, 0, encodedBigInteger.length);
			encodedBigInteger = dlpVerificationKey.getG3().toByteArray();
			hash.update(encodedBigInteger, 0, encodedBigInteger.length);
			hash.update(dlpVerificationKey.getZ0(), 0, dlpVerificationKey.getZ0().length);

			/**
			 * Process number of used Keys
			 */
			hash.update((byte) numberOfUsedKeys);

			/**
			 * Process queued KuKem ciphertext
			 */
			hash.update(kemCiphertext.getCiphertext(), 0, kemCiphertext.getCiphertext().length);
			while (!kuKemCiphertexts.isEmpty()) {
				BrkeKuKemCiphertext currentCiphertext = (BrkeKuKemCiphertext) kuKemCiphertexts.remove();
				HibeCiphertext hibeCiphertext = currentCiphertext.getCiphertext();
				hash.update(hibeCiphertext.getCom(), 0, hibeCiphertext.getCom().length);
				hash.update(hibeCiphertext.getCiphertext(), 0, hibeCiphertext.getCiphertext().length);
				hash.update(hibeCiphertext.getMacTag(), 0, hibeCiphertext.getMacTag().length);
			}
		} else {
			/**
			 * Process AssociatedData
			 */
			hash.update(associatedData, 0, associatedData.length);

			/**
			 * Process numberOfReceivedMessages
			 */
			hash.update((byte) numberOfReceivedMessages);

			/**
			 * Process BrkeKuKemPublicKey
			 */
			hash.update(kuKemPublicKey.getHibePublicParameter().getEncapsulationPublicParameter(), 0,
					kuKemPublicKey.getHibePublicParameter().getEncapsulationPublicParameter().length);
			hash.update(kuKemPublicKey.getHibePublicParameter().getEncodedPublicParameter(), 0,
					kuKemPublicKey.getHibePublicParameter().getEncodedPublicParameter().length);
			hash.update(kuKemPublicKey.getIdentityInformation(), 0, kuKemPublicKey.getIdentityInformation().length);
			hash.update((byte) kuKemPublicKey.getLevel());

			/**
			 * Process Signature Verification Key
			 */
			byte[] encodedBigInteger;
			encodedBigInteger = dlpVerificationKey.getG1().toByteArray();
			hash.update(encodedBigInteger, 0, encodedBigInteger.length);
			encodedBigInteger = dlpVerificationKey.getG2().toByteArray();
			hash.update(encodedBigInteger, 0, encodedBigInteger.length);
			encodedBigInteger = dlpVerificationKey.getG3().toByteArray();
			hash.update(encodedBigInteger, 0, encodedBigInteger.length);
			hash.update(dlpVerificationKey.getZ0(), 0, dlpVerificationKey.getZ0().length);

			/**
			 * Process number of used Keys
			 */
			hash.update((byte) numberOfUsedKeys);

			/**
			 * Process queued KuKem ciphertext
			 */
			hash.update(kemCiphertext.getCiphertext(), 0, kemCiphertext.getCiphertext().length);
		}
		hash.doFinal(output, 0);
		return output;
	}
}
