package de.rub.rkeinstantiation.factories;

import de.rub.rke.factories.TranscriptFactory;
import de.rub.rke.variables.Transcript;
import de.rub.rkeinstantiation.variables.BrkeTranscript;

/**
 * Factory for the BrkeTranscript.
 * 
 * @author Marco Smeets
 *
 */
public class BrkeTranscriptFactory implements TranscriptFactory {

	@Override
	public Transcript createTranscript() {
		return new BrkeTranscript();
	}

}
