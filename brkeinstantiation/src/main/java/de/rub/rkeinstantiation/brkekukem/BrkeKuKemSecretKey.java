package de.rub.rkeinstantiation.brkekukem;

import org.bouncycastle.util.Arrays;

import de.rub.rke.kukem.KuKemSecretKey;
import de.rub.rkeinstantiation.hibewrapper.HibeSecretKey;

/**
 * Class for the kuKem Secret Key.
 * 
 * @author Marco Smeets
 *
 */
public class BrkeKuKemSecretKey implements KuKemSecretKey {

	private HibeSecretKey hibeSecretKey;
	private byte[] identityInformation;
	private int level;

	public BrkeKuKemSecretKey(HibeSecretKey hibeSecretKey, byte[] identityInformation, int level) {
		this.hibeSecretKey = hibeSecretKey;
		this.identityInformation = Arrays.copyOf(identityInformation, identityInformation.length);
		this.level = level;
	}

	public HibeSecretKey getHibeSecretKey() {
		return hibeSecretKey;
	}

	public byte[] getIdentityInformation() {
		return identityInformation;
	}

	public int getLevel() {
		return level;
	}
}
