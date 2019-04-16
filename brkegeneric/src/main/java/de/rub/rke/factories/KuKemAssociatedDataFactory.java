package de.rub.rke.factories;

import de.rub.rke.brke.BrkeCiphertext;
import de.rub.rke.kukem.KuKemAssociatedData;
import de.rub.rke.variables.AssociatedData;

/**
 * Factory for the KuKem Associated Data.
 * 
 * Since the associated data depends on the realization of the kuKem, we let a
 * factory create the associated data.
 * 
 * @author Marco Smeets
 *
 */
public interface KuKemAssociatedDataFactory {

	public KuKemAssociatedData createAssociatedData(AssociatedData ad, BrkeCiphertext ciphertext);

}
