package de.rub.rke.queuedkukem;

import java.security.SecureRandom;
import java.util.LinkedList;
import java.util.Queue;

import de.rub.rke.brke.BrkeCiphertext;
import de.rub.rke.factories.KuKemAssociatedDataFactory;
import de.rub.rke.kem.KemKeyPair;
import de.rub.rke.kem.KemOutput;
import de.rub.rke.kem.KemPublicKey;
import de.rub.rke.kem.KemSecretKey;
import de.rub.rke.kem.KeyEncapsulationMechanism;
import de.rub.rke.kukem.KeyUpdateableKem;
import de.rub.rke.kukem.KuKemCiphertext;
import de.rub.rke.kukem.KuKemKeyPair;
import de.rub.rke.kukem.KuKemOutput;
import de.rub.rke.kukem.KuKemPublicKey;
import de.rub.rke.kukem.KuKemSecretKey;
import de.rub.rke.kukem.KuKemAssociatedData;
import de.rub.rke.variables.AssociatedData;
import de.rub.rke.variables.KeySeed;
import de.rub.rke.variables.SymmetricKey;

/**
 * Class that implements the kuKem functions in the Brke construction[1]. The
 * QueuedKuKem holds all keys and is responsible for key
 * updates/encapsulation/decapsulation It saves it's own secret Keys and the
 * public Keys of the communication Partner.
 * 
 * [1]Asynchronous ratcheted key exchange https://eprint.iacr.org/2018/296.pdf
 * 
 * @author Marco Smeets
 *
 */
public class QueuedKuKem {

	/**
	 * The publicKeyUpdateInformationList represents the transcript L_S from the
	 * BRKE construction[1].
	 */
	private KeyUpdateableKem kuKemAlgorithm;
	private KeyEncapsulationMechanism kemAlgorithm;
	private KuKemAssociatedDataFactory associatedDataFactory;
	private KemSecretKey kemSecretKey;
	private KemPublicKey communicationPartnerKemPublicKey;
	private Queue<KuKemSecretKey> secretKeys;
	private Queue<KuKemPublicKey> communicationPartnerPublicKeys;
	private LinkedList<KuKemAssociatedData> publicKeyUpdateInformationList;

	/**
	 * Constructor
	 * 
	 * @param kuKemAlgorithm
	 */
	public QueuedKuKem(KeyUpdateableKem kuKemAlgorithm, KeyEncapsulationMechanism kemAlgorithm,
			KuKemAssociatedDataFactory associatedDataFactory) {
		this.kuKemAlgorithm = kuKemAlgorithm;
		this.kemAlgorithm = kemAlgorithm;
		this.associatedDataFactory = associatedDataFactory;
		secretKeys = new LinkedList<KuKemSecretKey>();
		communicationPartnerPublicKeys = new LinkedList<KuKemPublicKey>();
		publicKeyUpdateInformationList = new LinkedList<KuKemAssociatedData>();
	}

	/**
	 * Initializes the QueuedKuKem
	 * 
	 * Generates and saves all relevant keys.
	 * 
	 * @param randomness - randomness for key generation
	 * @param initiator  - true (if initiator of conversation; false otherwise)
	 */
	public void init(SecureRandom randomness, boolean initiator) {
		KemKeyPair generatedKeyPair1 = kemAlgorithm.gen(randomness);
		KemKeyPair generatedKeyPair2 = kemAlgorithm.gen(randomness);
		if (initiator) {
			kemSecretKey = generatedKeyPair1.getSecretKey();
			communicationPartnerKemPublicKey = generatedKeyPair2.getPublicKey();
		} else {
			kemSecretKey = generatedKeyPair2.getSecretKey();
			communicationPartnerKemPublicKey = generatedKeyPair1.getPublicKey();
		}
	}

	/**
	 * Generates a kuKem key pair. Puts the secret key in the queue and returns the
	 * public key.
	 * 
	 * @param randomness - randomness used for key generation
	 * @return kuKem public key
	 */
	public KuKemPublicKey gen(SecureRandom randomness) {
		KuKemKeyPair generatedKeyPair = kuKemAlgorithm.gen(randomness);
		secretKeys.add(generatedKeyPair.getSecretKey());
		return generatedKeyPair.getPublicKey();
	}

	/**
	 * Generates a kuKem key pair. Puts the public key in the queue and discards the
	 * secret key.
	 * 
	 * @param seed - seed used for key generation
	 */
	public void addMatchingPublicKey(KeySeed seed) {
		KemKeyPair generatedKeyPair = kemAlgorithm.gen(seed);
		communicationPartnerKemPublicKey = generatedKeyPair.getPublicKey();
	}

	/**
	 * Encapsulates a symmetric key to all public keys that are currently in the
	 * queue. Used public keys are discarded.
	 * 
	 * @return QueuedKuKemOutput which contains a random symmetric key and a
	 *         queuedKuKem Ciphertext.
	 */
	public QueuedKuKemOutput encapsulate() {
		if (communicationPartnerKemPublicKey == null) {
			// TODO: Throw Exception
			return null;
		}
		KemOutput kemOutput = kemAlgorithm.encapsulate(communicationPartnerKemPublicKey);
		communicationPartnerKemPublicKey = null;
		int numberOfEncapsulations = 1;
		SymmetricKey generatedKey = kemOutput.getKey();
		if (!communicationPartnerPublicKeys.isEmpty()) {
			Queue<KuKemCiphertext> ciphertext = new LinkedList<KuKemCiphertext>();
			while (!communicationPartnerPublicKeys.isEmpty()) {
				KuKemOutput kuKemOutput = kuKemAlgorithm.encapsulate(communicationPartnerPublicKeys.poll());
				numberOfEncapsulations++;
				generatedKey.mixToKey(kuKemOutput.getKey());
				ciphertext.add(kuKemOutput.getCiphertext());
			}
			return new QueuedKuKemOutput(generatedKey,
					new QueuedKuKemCiphertext(kemOutput.getCiphertext(), numberOfEncapsulations, ciphertext));
		}
		return new QueuedKuKemOutput(generatedKey,
				new QueuedKuKemCiphertext(kemOutput.getCiphertext(), numberOfEncapsulations, null));
	}

	/**
	 * Decapsulates a QueuedKuKemCiphertext to a symmetric key. Uses the amount of
	 * secret keys that is specified in 'numberOfUsedKeysForEncapsulation'. Used
	 * secret keys are discarded.
	 * 
	 * @param numberOfUsedKeysForEncapsulation
	 * @param ciphertext
	 * @return decapsulated key
	 */
	public SymmetricKey decapsulate(int numberOfUsedKeysForEncapsulation, QueuedKuKemCiphertext ciphertext) {
		if (numberOfUsedKeysForEncapsulation == 1) {
			SymmetricKey generatedKey = kemAlgorithm.decapsulate(kemSecretKey, ciphertext.getKemCiphertext());
			kemSecretKey = null;
			return generatedKey;
		} else {
			Queue<KuKemCiphertext> ciphertexts = new LinkedList<KuKemCiphertext>(ciphertext.getKuKemCiphertexts());
			SymmetricKey generatedKey = kemAlgorithm.decapsulate(kemSecretKey, ciphertext.getKemCiphertext());
			for (int i = 0; i < numberOfUsedKeysForEncapsulation - 1; i++) {
				generatedKey.mixToKey(kuKemAlgorithm.decapsulate(secretKeys.remove(), ciphertexts.remove()));
			}
			return generatedKey;
		}
	}

	/**
	 * Updates all secret keys.
	 * 
	 * @param seed       - seed used to generate the first secret key
	 * @param ad         - associatedData used for the key update
	 * @param ciphertext - ciphertext used for the key update
	 */
	public void updateSecretKeys(KeySeed seed, AssociatedData ad, BrkeCiphertext ciphertext) {
		kemSecretKey = kemAlgorithm.gen(seed).getSecretKey();
		Queue<KuKemSecretKey> updatedSecretKeys = new LinkedList<KuKemSecretKey>();
		KuKemAssociatedData kuKemAssociatedData = associatedDataFactory.createAssociatedData(ad, ciphertext);
		while (!secretKeys.isEmpty()) {
			updatedSecretKeys.add(kuKemAlgorithm.updateSecretKey(secretKeys.remove(), kuKemAssociatedData));
		}
		secretKeys = updatedSecretKeys;
	}

	/**
	 * Adds a public key and updates it if necessary. Furthermore, deletes all
	 * ciphertexts that are not required anymore, because the communication partner
	 * received the messages.
	 * 
	 * @param publicKey                 - public key to be added
	 * @param messagesReceivedByPartner - number of messages received by
	 *                                  communication partner
	 * @param NumberOfUpdates           - number of required updates
	 */
	public void addUpdatedPublicKey(KuKemPublicKey publicKey, int messagesReceivedByPartner, int NumberOfUpdates) {
		while (messagesReceivedByPartner > 0) {
			publicKeyUpdateInformationList.remove();
			messagesReceivedByPartner--;
		}
		for (int i = 0; i < NumberOfUpdates; i++) {
			publicKey = kuKemAlgorithm.updatePublicKey(publicKey, publicKeyUpdateInformationList.get(i));
		}
		communicationPartnerPublicKeys.add(publicKey);
	}

	/**
	 * Stores a ciphertext in the updateInformation queue, which is needed to update
	 * public keys, if the communication partner did not receive a message yet.
	 * 
	 * @param ad
	 * @param ciphertext
	 */
	public void addToPublicKeyUpdateInformationQueue(AssociatedData ad, BrkeCiphertext ciphertext) {
		publicKeyUpdateInformationList.add(associatedDataFactory.createAssociatedData(ad, ciphertext));
	}

	/**
	 * @return number of saved public keys
	 */
	public int getNumberOfSavedPublicKeys() {
		return communicationPartnerPublicKeys.size() + 1;
	}
}
