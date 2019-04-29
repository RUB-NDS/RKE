package de.rub.brkeevaluation.seclevel100algorithms;

import org.bouncycastle.crypto.agreement.DHStandardGroups;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.DHParameters;

import de.rub.rke.factories.SignatureFactory;
import de.rub.rke.signature.SignatureManager;
import de.rub.rkeinstantiation.brkesignature.DLPChameleonOTSignatureManager;

/**
 * Test Factory for the DLP-Based Signature with a diffie-hellman group with
 * symmetric equivalent strength of 100Bit.
 * 
 * 
 * [1] Negotiated Finite Field Diffie-Hellman Ephemeral Parameters for Transport
 * Layer Security (TLS) https://tools.ietf.org/html/rfc7919
 * 
 * @author Marco Smeets
 *
 */
public class DLPChameleon100BitSignatureFactory implements SignatureFactory {

	/**
	 * Creates a DLP-Based Signature Algorithm with the SHA256 as hash function and
	 * the Diffie Hellman group from RFC7919[1], which uses a group with a 2048 Bit
	 * prime.
	 */
	@Override
	public SignatureManager createSignatureManager() {
		DHParameters groupParameters = DHStandardGroups.rfc7919_ffdhe2048;
		SHA256Digest hash = new SHA256Digest();
		return new DLPChameleonOTSignatureManager(groupParameters, hash);
	}
}
