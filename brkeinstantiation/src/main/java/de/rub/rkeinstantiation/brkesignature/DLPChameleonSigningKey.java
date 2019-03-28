package de.rub.rkeinstantiation.brkesignature;

import java.math.BigInteger;

import org.bouncycastle.util.Arrays;

import de.rub.rke.signature.SignatureSigningKey;

/**
 * Class for the signing key of the DLP-Based Signature
 * 
 * @author Marco Smeets
 *
 */
public class DLPChameleonSigningKey implements SignatureSigningKey {

	private BigInteger x1inv;
	private BigInteger x2inv;
	private BigInteger r1;
	private BigInteger r2;
	private byte[] z1;

	public DLPChameleonSigningKey(BigInteger x1inv, BigInteger x2inv, BigInteger r1, BigInteger r2, byte[] z1) {
		this.x1inv = x1inv;
		this.x2inv = x2inv;
		this.r1 = r1;
		this.r2 = r2;
		this.z1 = Arrays.copyOf(z1, z1.length);
	}

	public BigInteger getX1Inv() {
		return x1inv;
	}

	public BigInteger getX2Inv() {
		return x2inv;
	}

	public BigInteger getR1() {
		return r1;
	}

	public BigInteger getR2() {
		return r2;
	}

	public byte[] getZ1() {
		return z1;
	}
}
