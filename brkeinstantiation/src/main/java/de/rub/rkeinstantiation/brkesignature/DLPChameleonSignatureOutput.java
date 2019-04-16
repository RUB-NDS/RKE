package de.rub.rkeinstantiation.brkesignature;

import java.math.BigInteger;

import de.rub.rke.signature.SignatureOutput;

/**
 * Class for the output of the DLP-Based Signature
 * 
 * @author Marco Smeets
 *
 */
public class DLPChameleonSignatureOutput implements SignatureOutput {

	private BigInteger sign0;
	private BigInteger sign1;

	/**
	 * We need a empty constructor to reconstruct the objects from JSON.
	 */
	@SuppressWarnings("unused")
	private DLPChameleonSignatureOutput() {
	}

	public DLPChameleonSignatureOutput(BigInteger sign0, BigInteger sign1) {
		this.sign0 = sign0;
		this.sign1 = sign1;
	}

	public BigInteger getSign0() {
		return sign0;
	}

	public BigInteger getSign1() {
		return sign1;
	}
}
