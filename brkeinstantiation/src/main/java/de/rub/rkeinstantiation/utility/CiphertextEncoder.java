package de.rub.rkeinstantiation.utility;

import java.io.IOException;
import java.util.Base64;
import java.util.LinkedList;
import java.util.Queue;

import org.bouncycastle.crypto.digests.SHA512Digest;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleAbstractTypeResolver;
import com.fasterxml.jackson.databind.module.SimpleModule;

import de.rub.rke.brke.BrkeCiphertext;
import de.rub.rke.kem.KemCiphertext;
import de.rub.rke.kukem.KuKemCiphertext;
import de.rub.rke.kukem.KuKemPublicKey;
import de.rub.rke.queuedkukem.QueuedKuKemCiphertext;
import de.rub.rke.signature.SignatureOutput;
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
			hash.update(kuKemPublicKey.getHibePublicParameter().getEncodedHibePublicParameter(), 0,
					kuKemPublicKey.getHibePublicParameter().getEncodedHibePublicParameter().length);
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
			hash.update(kuKemPublicKey.getHibePublicParameter().getEncodedHibePublicParameter(), 0,
					kuKemPublicKey.getHibePublicParameter().getEncodedHibePublicParameter().length);
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
			hash.update(kuKemPublicKey.getHibePublicParameter().getEncodedHibePublicParameter(), 0,
					kuKemPublicKey.getHibePublicParameter().getEncodedHibePublicParameter().length);
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
			hash.update(kuKemPublicKey.getHibePublicParameter().getEncodedHibePublicParameter(), 0,
					kuKemPublicKey.getHibePublicParameter().getEncodedHibePublicParameter().length);
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

	/**
	 * Converts a BrkeCiphertext generated from BRKE (with AlgorithmSet1) to JSON
	 * with Base64 encoding.
	 * 
	 * @param ciphertext
	 * @return encodedCiphertext
	 */
	public static byte[] ciphertextToBase64(BrkeCiphertext ciphertext) {
		ObjectMapper ow = new ObjectMapper();
		byte[] json = null;
		try {
			json = ow.writeValueAsBytes(ciphertext);
		} catch (JsonProcessingException e) {
			return null;
		}
		byte[] base64encoded = Base64.getEncoder().encode(json);
		return base64encoded;
	}

	/**
	 * Converts a BrkeCiphertext JSON object (Base64 encoded) to a BrkeCiphertext
	 * (generated with Algorithm Set 1).
	 * 
	 * @param base64encoded
	 * @return
	 */
	public static BrkeCiphertext base64ToCiphertext(byte[] base64encoded) {
		ObjectMapper ow = new ObjectMapper();
		byte[] json = Base64.getDecoder().decode(base64encoded);
		BrkeCiphertext ciphertext = null;
		/**
		 * Load the implementations of the interfaces.
		 */
		SimpleModule module = new SimpleModule("CustomModel", Version.unknownVersion());
		SimpleAbstractTypeResolver resolver = new SimpleAbstractTypeResolver();
		resolver.addMapping(KuKemPublicKey.class, BrkeKuKemPublicKey.class);
		resolver.addMapping(SignatureVerificationKey.class, DLPChameleonVerificationKey.class);
		resolver.addMapping(SignatureOutput.class, DLPChameleonSignatureOutput.class);
		resolver.addMapping(KemCiphertext.class, ECIESKemCiphertext.class);
		resolver.addMapping(KuKemCiphertext.class, BrkeKuKemCiphertext.class);
		module.setAbstractTypes(resolver);
		ow.registerModule(module);
		try {
			ciphertext = ow.readValue(json, BrkeCiphertext.class);
		} catch (IOException e) {
			return null;
		}
		return ciphertext;
	}
}
