package org.springframework.security.saml.web;

import org.apache.commons.lang.StringUtils;
import org.opensaml.xml.security.CriteriaSet;
import org.springframework.security.saml.key.KeyManager;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.SecurityException;

import java.security.cert.X509Certificate;
import java.util.*;

public class ChainedKeyManager implements KeyManager {
    private final List<KeyManager> keyManagers;

    public ChainedKeyManager(List<KeyManager> keyManagers) {
        this.keyManagers = keyManagers;
    }

    @Override
    public Credential getCredential(final String keyName) {
        for (final KeyManager km : keyManagers) {
            final Credential cred = km.getCredential(keyName);
            if (cred != null) {
                return cred;
            }
        }

        return null;
    }

    @Override
    public Credential getDefaultCredential() {
        for (final KeyManager km : keyManagers) {
            final Credential cred = km.getDefaultCredential();
            if (cred != null) {
                return cred;
            }
        }

        return null;
    }

    @Override
    public String getDefaultCredentialName() {
        for (final KeyManager km : keyManagers) {
            final String name = km.getDefaultCredentialName();
            if (StringUtils.isNotEmpty(name)) {
                return name;
            }
        }

        return null;
    }

    @Override
    public Set<String> getAvailableCredentials() {
        final Set<String> availableCredentials = new HashSet<>();
        for (final KeyManager km : keyManagers) {
            final Set<String> credentials = km.getAvailableCredentials();
            if (credentials != null) {
                availableCredentials.addAll(credentials);
            }
        }

        return Collections.unmodifiableSet(availableCredentials);
    }

    @Override
    public X509Certificate getCertificate(final String alias) {
        for (final KeyManager km : keyManagers) {
            final X509Certificate cert = km.getCertificate(alias);
            if (cert != null) {
                return cert;
            }
        }

        return null;
    }

    @Override
    public Iterable<Credential> resolve(final CriteriaSet criteriaSet) throws SecurityException {
        final List<Credential> allCredentials = new ArrayList<>();

        for (final KeyManager km : keyManagers) {
            final Iterable<Credential> credentials = km.resolve(criteriaSet);
            if (credentials != null) {
                for (final Credential cred : credentials) {
                    allCredentials.add(cred);
                }
            }
        }

        return Collections.unmodifiableList(allCredentials);
    }

    @Override
    public Credential resolveSingle(final CriteriaSet criteriaSet) throws SecurityException {
        for (final KeyManager km : keyManagers) {
            final Credential cred = km.resolveSingle(criteriaSet);
            if (cred != null) {
                return cred;
            }
        }

        return null;
    }
}
