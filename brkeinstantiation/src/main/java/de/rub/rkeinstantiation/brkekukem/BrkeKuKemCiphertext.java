package de.rub.rkeinstantiation.brkekukem;

import de.rub.rke.kukem.KuKemCiphertext;
import de.rub.rkeinstantiation.hibewrapper.HibeCiphertext;

/**
 * Class for the kuKem Ciphertext
 * 
 * @author Marco Smeets
 *
 */
public class BrkeKuKemCiphertext implements KuKemCiphertext {

	private HibeCiphertext ciphertext;

	/**
	 * We need a empty constructor to reconstruct the objects from JSON.
	 */
	@SuppressWarnings("unused")
	private BrkeKuKemCiphertext() {
	}

	public BrkeKuKemCiphertext(HibeCiphertext ciphertext) {
		this.ciphertext = ciphertext;
	}

	public HibeCiphertext getCiphertext() {
		return ciphertext;
	}
}
