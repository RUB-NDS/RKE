package de.rub.rkeinstantiation.factories;

import org.bouncycastle.crypto.agreement.DHStandardGroups;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.DHParameters;

import de.rub.rke.factories.SignatureFactory;
import de.rub.rke.signature.SignatureAlgorithm;
import de.rub.rkeinstantiation.brkesignature.DLPChameleonOTSignatureAlgorithm;

/**
 * Factory for the DLP-Based Signature.
 * 
 * 
 * [1] Negotiated Finite Field Diffie-Hellman Ephemeral Parameters for Transport Layer Security (TLS) 
 * https://tools.ietf.org/html/rfc7919
 * [2] Algorithms, Key Size and Protocols Report (2018)
 * http://www.ecrypt.eu.org/csa/documents/D5.4-FinalAlgKeySizeProt.pdf
 * 
 * @author Marco Smeets
 *
 */
public class DLPChameleonSignatureFactory implements SignatureFactory {

	/**
	 * Creates a DLP-Based Signature Algorithm with the SHA256 as hash function and
	 * the Diffie Hellman group from RFC7919[1], which uses a group with a 3072 Bit
	 * prime, as recommended in [2].
	 */
	@Override
	public SignatureAlgorithm createSignatureAlgorithm() {
		DHParameters groupParameters = DHStandardGroups.rfc7919_ffdhe3072;
		SHA256Digest hash = new SHA256Digest();
		return new DLPChameleonOTSignatureAlgorithm(groupParameters, hash);
	}

}
