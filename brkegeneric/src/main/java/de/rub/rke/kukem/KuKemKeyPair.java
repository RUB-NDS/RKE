package de.rub.rke.kukem;

/**
 * Interface for the key pair used for a kuKem
 * 
 * @author Marco Smeets
 *
 */
public interface KuKemKeyPair {

	KuKemSecretKey getSecretKey();

	KuKemPublicKey getPublicKey();
}
