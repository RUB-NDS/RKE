package de.rub.rkeinstantiation.brkesignature;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.Queue;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.generators.DHKeyPairGenerator;
import org.bouncycastle.crypto.params.DHKeyGenerationParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;

import de.rub.rke.brke.BrkeCiphertext;
import de.rub.rke.kukem.KuKemPublicKey;
import de.rub.rke.queuedkukem.QueuedKuKemCiphertext;
import de.rub.rke.signature.SignatureAlgorithm;
import de.rub.rke.signature.SignatureOutput;
import de.rub.rke.signature.SignatureVerificationKey;
import de.rub.rke.variables.AssociatedData;
import de.rub.rke.variables.KeySeed;
import de.rub.rkeinstantiation.utility.CiphertextEncoder;

/**
 * Class which implements the One-Time Signature, which is used in the Brke
 * construction. We use a Chameleon Hash function based on the DLP Problem to
 * construct a SUF-CMA secure One-Time Signature scheme as described by
 * Mohassel[1].
 * 
 * [1] One-Time Signatures and Chameleon Hash Functions
 * https://link.springer.com/content/pdf/10.1007/978-3-642-19574-7_21.pdf
 * 
 * @author Marco Smeets
 *
 */
public class DLPChameleonOTSignatureAlgorithm implements SignatureAlgorithm {

	private DHParameters groupParameters;
	private Digest hash;
	private BigInteger p;
	private BigInteger order;
	private BigInteger generator;
	private int bitlength;

	private Queue<DLPChameleonSigningKey> signingKeys;
	private DLPChameleonVerificationKey communicationPartnerVerificationKey;

	/**
	 * Constructs a One-Time Signature scheme based on a DLP Chameleon Hash
	 * function. Since [1] requires a Hash function so that the signature is SUF-CMA
	 * secure, we have to provide a hash function to the signature algorithm.
	 * Furthermore, we have to provide group Parameters to the signature scheme. The
	 * idea is to use a established Diffie Hellman group, where the CDH Problem is
	 * hard, and use it in the signature scheme.
	 * 
	 * @param groupParameters - Diffie Hellman group parameter
	 * @param hash            - hash function
	 */
	public DLPChameleonOTSignatureAlgorithm(DHParameters groupParameters, Digest hash) {
		this.groupParameters = groupParameters;
		this.hash = hash;
		p = groupParameters.getP();
		order = groupParameters.getQ();
		generator = groupParameters.getG();
		bitlength = order.bitLength();
		signingKeys = new LinkedList<DLPChameleonSigningKey>();
	}

	/**
	 * Initializes the Signature Scheme. Key Generation is performed as described in
	 * [1].
	 */
	@Override
	public void init(SecureRandom randomness, boolean initiator) {
		DHKeyGenerationParameters generationParameters = new DHKeyGenerationParameters(randomness, groupParameters);
		DHKeyPairGenerator dhKeyGenerator = new DHKeyPairGenerator();
		dhKeyGenerator.init(generationParameters);
		DLPChameleonSigningKey signingKey[] = new DLPChameleonSigningKey[2];
		DLPChameleonVerificationKey verificationKey[] = new DLPChameleonVerificationKey[2];
		for (int i = 0; i < 2; i++) {
			BigInteger x1 = ((DHPrivateKeyParameters) dhKeyGenerator.generateKeyPair().getPrivate()).getX();
			BigInteger x2 = ((DHPrivateKeyParameters) dhKeyGenerator.generateKeyPair().getPrivate()).getX();
			BigInteger g2 = generator.modPow(x1, p);
			BigInteger g3 = generator.modPow(x2, p);
			BigInteger r1 = new BigInteger(bitlength, randomness);
			BigInteger r2 = new BigInteger(bitlength, randomness);
			BigInteger g2r = g2.modPow(r1, p);
			BigInteger g3r = g3.modPow(r2, p);

			BigInteger g1g2r = generator.multiply(g2r).mod(p);
			BigInteger g1g3r = generator.multiply(g3r).mod(p);

			byte[] encodedg1g2r = g1g2r.toByteArray();
			byte[] encodedg1g3r = g1g3r.toByteArray();

			byte[] z0 = new byte[hash.getDigestSize()];
			byte[] z1 = new byte[hash.getDigestSize()];

			hash.update(encodedg1g2r, 0, encodedg1g2r.length);
			hash.doFinal(z0, 0);
			hash.reset();
			hash.update(encodedg1g3r, 0, encodedg1g3r.length);
			hash.doFinal(z1, 0);
			hash.reset();

			BigInteger invx1 = x1.modInverse(order);
			BigInteger invx2 = x2.modInverse(order);
			signingKey[i] = new DLPChameleonSigningKey(invx1, invx2, r1, r2, z1);
			verificationKey[i] = new DLPChameleonVerificationKey(generator, g2, g3, z0);
		}
		if (initiator) {
			signingKeys.add(signingKey[0]);
			communicationPartnerVerificationKey = verificationKey[1];
		} else {
			signingKeys.add(signingKey[1]);
			communicationPartnerVerificationKey = verificationKey[0];
		}
	}

	/**
	 * Generates a key Pair for the Signature, saves the signing key and outputs the
	 * verification key.
	 */
	@Override
	public SignatureVerificationKey gen(SecureRandom randomness) {
		DHKeyGenerationParameters generationParameters = new DHKeyGenerationParameters(randomness, groupParameters);
		DHKeyPairGenerator dhKeyGenerator = new DHKeyPairGenerator();
		dhKeyGenerator.init(generationParameters);
		BigInteger x1 = ((DHPrivateKeyParameters) dhKeyGenerator.generateKeyPair().getPrivate()).getX();
		BigInteger x2 = ((DHPrivateKeyParameters) dhKeyGenerator.generateKeyPair().getPrivate()).getX();
		BigInteger g2 = generator.modPow(x1, p);
		BigInteger g3 = generator.modPow(x2, p);
		BigInteger r1 = new BigInteger(bitlength, randomness);
		BigInteger r2 = new BigInteger(bitlength, randomness);
		BigInteger g2r = g2.modPow(r1, p);
		BigInteger g3r = g3.modPow(r2, p);

		BigInteger g1g2r = (generator.multiply(g2r)).mod(p);
		BigInteger g1g3r = generator.multiply(g3r).mod(p);

		byte[] encodedg1g2r = g1g2r.toByteArray();
		byte[] encodedg1g3r = g1g3r.toByteArray();

		byte[] z0 = new byte[hash.getDigestSize()];
		byte[] z1 = new byte[hash.getDigestSize()];

		hash.update(encodedg1g2r, 0, encodedg1g2r.length);
		hash.doFinal(z0, 0);
		hash.reset();
		hash.update(encodedg1g3r, 0, encodedg1g3r.length);
		hash.doFinal(z1, 0);
		hash.reset();

		BigInteger invx1 = x1.modInverse(order);
		BigInteger invx2 = x2.modInverse(order);

		signingKeys.add(new DLPChameleonSigningKey(invx1, invx2, r1, r2, z1));
		return new DLPChameleonVerificationKey(generator, g2, g3, z0);
	}

	/**
	 * We do not use this function in the brke construction.
	 */
	@Override
	public SignatureVerificationKey gen(KeySeed arg0) {
		// TODO Auto-generated method stub
		return null;
	}

	/**
	 * Saves a verification key.
	 */
	@Override
	public void setVerificationKey(SignatureVerificationKey verificationKey) {
		this.communicationPartnerVerificationKey = (DLPChameleonVerificationKey) verificationKey;
	}

	/**
	 * Signs the provided brke ciphertext parts and associated data as described in
	 * [1].
	 */
	@Override
	public SignatureOutput sign(AssociatedData associatedData, int numberOfReceivedMessages, KuKemPublicKey publicKey,
			SignatureVerificationKey verificationKey, int numberOfUsedKeys, QueuedKuKemCiphertext ciphertext) {
		byte[] hashedInput = CiphertextEncoder.hashAdCiphertextPartsForSigning(associatedData, numberOfReceivedMessages,
				publicKey, verificationKey, numberOfUsedKeys, ciphertext);
		DLPChameleonSigningKey signingKey = signingKeys.poll();
		if (signingKey == null) {
			// TODO: Throw Exception.
			return null;
		}
		BigInteger message = new BigInteger(hashedInput);
		BigInteger sign0 = signingKey.getX2Inv().multiply(BigInteger.ONE.subtract(message).mod(order)).mod(order);
		sign0 = (sign0.add(signingKey.getR2())).mod(order);
		BigInteger z1Int = new BigInteger(signingKey.getZ1());
		BigInteger sign1 = signingKey.getX1Inv().multiply(BigInteger.ONE.subtract(z1Int).mod(order)).mod(order);
		sign1 = (sign1.add(signingKey.getR1())).mod(order);

		return new DLPChameleonSignatureOutput(sign0, sign1);
	}

	/**
	 * Verifies a signed brke ciphertext as described in [1].
	 */
	@Override
	public boolean verify(AssociatedData associatedData, BrkeCiphertext ciphertext) {
		DLPChameleonSignatureOutput signatureOutput = (DLPChameleonSignatureOutput) ciphertext.getSignature();
		byte[] hashedInput = CiphertextEncoder.hashAdCiphertextPartsForSigning(associatedData,
				ciphertext.getNumberOfReceivedMessages(), ciphertext.getPublicKey(), ciphertext.getVerificationKey(),
				ciphertext.getNumberOfUsedKeys(), ciphertext.getCiphertext());
		if (communicationPartnerVerificationKey == null) {
			// TODO: Throw exception
			return false;
		}
		BigInteger message = new BigInteger(hashedInput);
		BigInteger g1m = communicationPartnerVerificationKey.getG1().modPow(message, p);
		BigInteger g3sign0 = communicationPartnerVerificationKey.getG3().modPow(signatureOutput.getSign0(), p);
		BigInteger g1mg3sign0 = g1m.multiply(g3sign0).mod(p);
		byte[] encodedg1mg3sign0 = g1mg3sign0.toByteArray();
		byte[] hashVer = new byte[hash.getDigestSize()];

		hash.update(encodedg1mg3sign0, 0, encodedg1mg3sign0.length);
		hash.doFinal(hashVer, 0);
		hash.reset();
		BigInteger hashInt = new BigInteger(hashVer);
		BigInteger g1hashInt = communicationPartnerVerificationKey.getG1().modPow(hashInt, p);
		BigInteger g2Sign1 = communicationPartnerVerificationKey.getG2().modPow(signatureOutput.getSign1(), p);
		BigInteger finalInt = (g1hashInt.multiply(g2Sign1)).mod(p);
		byte[] encodedfinalInt = finalInt.toByteArray();
		byte[] result = new byte[hash.getDigestSize()];
		hash.update(encodedfinalInt, 0, encodedfinalInt.length);
		hash.doFinal(result, 0);
		hash.reset();

		if (Arrays.equals(result, communicationPartnerVerificationKey.getZ0())) {
			return true;
		}
		return false;
	}

}
