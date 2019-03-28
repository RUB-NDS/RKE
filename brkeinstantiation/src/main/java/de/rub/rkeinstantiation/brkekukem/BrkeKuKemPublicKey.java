package de.rub.rkeinstantiation.brkekukem;

import org.bouncycastle.util.Arrays;

import de.rub.rke.kukem.KuKemPublicKey;
import de.rub.rkeinstantiation.hibewrapper.HibePublicParameter;

/**
 * Class for the kuKem public key.
 * 
 * @author Marco Smeets
 *
 */
public class BrkeKuKemPublicKey implements KuKemPublicKey {

	private HibePublicParameter hibePublicParameter;
	private byte[] identityInformation;
	private int level;

	public BrkeKuKemPublicKey(HibePublicParameter hibePublicParameter, byte[] identityInformation, int level) {
		this.hibePublicParameter = hibePublicParameter;
		this.identityInformation = Arrays.copyOf(identityInformation, identityInformation.length);
		this.level = level;
	}

	public void appendIdentityInformation(byte[] identityInformation) {
		byte[] newIdentityInformation = new byte[this.identityInformation.length + identityInformation.length];
		System.arraycopy(this.identityInformation, 0, newIdentityInformation, 0, this.identityInformation.length);
		System.arraycopy(identityInformation, 0, newIdentityInformation, this.identityInformation.length,
				identityInformation.length);
		this.identityInformation = Arrays.copyOf(newIdentityInformation, newIdentityInformation.length);
		level++;
	}

	public HibePublicParameter getHibePublicParameter() {
		return hibePublicParameter;
	}

	public byte[] getIdentityInformation() {
		return identityInformation;
	}

	public int getLevel() {
		return level;
	}
}
