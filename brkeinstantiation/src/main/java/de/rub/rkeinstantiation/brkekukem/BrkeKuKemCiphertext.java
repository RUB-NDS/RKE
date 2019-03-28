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

	public BrkeKuKemCiphertext(HibeCiphertext ciphertext) {
		this.ciphertext = ciphertext;
	}

	public HibeCiphertext getCiphertext() {
		return ciphertext;
	}
}
