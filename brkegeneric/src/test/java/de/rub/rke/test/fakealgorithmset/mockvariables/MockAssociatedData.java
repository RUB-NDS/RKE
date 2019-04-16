package de.rub.rke.test.fakealgorithmset.mockvariables;

import de.rub.rke.variables.AssociatedData;

/**
 * Implementation of AssociatedData.
 * 
 * Uses int to represent associated data, as every other fake class.
 * 
 * @author Marco Smeets
 *
 */
public class MockAssociatedData implements AssociatedData {

	int associatedData;

	public MockAssociatedData(int associatedData) {
		this.associatedData = associatedData;
	}

	public int getIntRepresentation() {
		return associatedData;
	}
}
