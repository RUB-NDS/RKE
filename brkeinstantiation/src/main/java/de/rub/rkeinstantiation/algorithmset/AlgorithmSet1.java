package de.rub.rkeinstantiation.algorithmset;

import de.rub.rke.brke.BrkeAlgorithmSet;

import de.rub.rkeinstantiation.factories.BrkeKuKemAssociatedDataFactory;
import de.rub.rkeinstantiation.factories.BrkeKuKemFactory;
import de.rub.rkeinstantiation.factories.BrkeTranscriptFactory;
import de.rub.rkeinstantiation.factories.DLPChameleonSignatureFactory;
import de.rub.rkeinstantiation.factories.ECIESKemFactory;
import de.rub.rkeinstantiation.factories.HKDFRandomOracleFactory;

/**
 * Algorithm Set for the Brke Construction. Uses:
 * HIBE (for kuKem): Lewko-Waters Hibe (prime order translation)[1] 
 * Kem: ECIES-Kem[2]
 * Hash/Rom: HKDF[3]
 * Signature: One-Time Signature based on DLP-Chameleon Hash Function[4]
 * 
 * Hash Functions used within the algorithms: SHA256/SHA512 (currently)
 * 
 * 
 * [1] Tools for Simulating Features of Composite Order Bilinear Groups in the
 * Prime Order Setting
 * https://link.springer.com/content/pdf/10.1007/978-3-642-29011-4_20.pdf 
 * [2] ISO/IEC 18033-2: Information techology - Security techniques 
 * Encryption algorithms - Part 2: Asymmetric Ciphers
 * https://www.shoup.net/iso/std4.pdf
 * [3] Cryptographic Extraction and Key Derivation: The HKDF Scheme
 * https://link.springer.com/content/pdf/10.1007/978-3-642-14623-7_34.pdf 
 * [4]One-Time Signatures and Chameleon Hash Functions
 * https://link.springer.com/content/pdf/10.1007/978-3-642-19574-7_21.pdf
 * 
 * @author Marco Smeets
 */
public class AlgorithmSet1 extends BrkeAlgorithmSet {

	public AlgorithmSet1(BrkeKuKemFactory kuKemFactory, ECIESKemFactory kemFactory,
			HKDFRandomOracleFactory randomOracle, BrkeKuKemAssociatedDataFactory associatedDataFactory,
			DLPChameleonSignatureFactory signatureFactory, BrkeTranscriptFactory transcriptFactory) {
		super(kuKemFactory, kemFactory, randomOracle, associatedDataFactory, signatureFactory, transcriptFactory);
	}

}
