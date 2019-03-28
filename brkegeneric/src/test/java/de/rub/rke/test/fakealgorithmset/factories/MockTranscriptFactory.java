package de.rub.rke.test.fakealgorithmset.factories;

import de.rub.rke.factories.TranscriptFactory;
import de.rub.rke.test.fakealgorithmset.mockvariables.MockTranscript;
import de.rub.rke.variables.Transcript;

/**
 * Implementation of Transcript factory that returns a transcript
 * 
 * @author Marco Smeets
 *
 */
public class MockTranscriptFactory implements TranscriptFactory {

	@Override
	public Transcript createTranscript() {
		return new MockTranscript();
	}

}
