package de.rub.rkeinstantiation.brkesignature;

import java.math.BigInteger;
import java.util.Arrays;

import de.rub.rke.signature.SignatureVerificationKey;

/**
 * Class for the verification key of the DLP-Based Signature
 * 
 * @author Marco Smeets
 *
 */
public class DLPChameleonVerificationKey implements SignatureVerificationKey {

	private BigInteger g1;
	private BigInteger g2;
	private BigInteger g3;
	private byte[] z0;

	public DLPChameleonVerificationKey(BigInteger g1, BigInteger g2, BigInteger g3, byte[] z0) {
		this.g1 = g1;
		this.g2 = g2;
		this.g3 = g3;
		this.z0 = Arrays.copyOf(z0, z0.length);
	}

	public BigInteger getG1() {
		return g1;
	}

	public BigInteger getG2() {
		return g2;
	}

	public BigInteger getG3() {
		return g3;
	}

	public byte[] getZ0() {
		return z0;
	}
}
