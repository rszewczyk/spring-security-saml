package org.springframework.security.saml.web;

import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.criteria.UsageCriteria;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.springframework.security.saml.key.KeyManager;

import java.security.cert.X509Certificate;
import java.util.*;

public class DatabaseTrustedKeyManager implements KeyManager {
    private final X509Repository x509Repository;
    private final String defaultCredentialName;

    public DatabaseTrustedKeyManager(final X509Repository x509Repository) {
        this(x509Repository, null);
    }

    public DatabaseTrustedKeyManager(final X509Repository x509Repository, final String defaultCredentialName) {
        this.x509Repository = x509Repository;
        this.defaultCredentialName = defaultCredentialName;
    }

    @Override
    public Credential getDefaultCredential() {
        return getCredential(defaultCredentialName);
    }

    @Override
    public String getDefaultCredentialName() {
        return defaultCredentialName;
    }

    @Override
    public X509Certificate getCertificate(final String alias) {
        return x509Repository.get(alias);
    }

    @Override
    public Set<String> getAvailableCredentials() {
        return x509Repository.getAvailableNames();
    }

    @Override
    public Credential resolveSingle(final CriteriaSet criteria) throws SecurityException {
        final Iterator<Credential> credentials = resolve(criteria).iterator();
        if (credentials.hasNext()) {
            return credentials.next();
        } else {
            return null;
        }
    }

    @Override
    public Iterable<Credential> resolve(final CriteriaSet criteria) throws SecurityException {
        final String entityID = criteria.get(EntityIDCriteria.class).getEntityID();

        final UsageCriteria usageCriteria = criteria.get(UsageCriteria.class);
        final UsageType usage = usageCriteria != null ? usageCriteria.getUsage() : UsageType.UNSPECIFIED;

        X509Certificate cert = x509Repository.get(entityID);
        if (cert != null) {
            return Collections.singletonList(buildCredential(cert, entityID, usage));
        }

        return Collections.emptyList();
    }

    @Override
    public Credential getCredential(final String keyName) {
        final X509Certificate cert = x509Repository.get(keyName);
        if (cert != null) {
            return buildCredential(cert, keyName, UsageType.UNSPECIFIED);
        }

        return null;
    }

    private static Credential buildCredential(final X509Certificate certificate, final String entityID, final UsageType usage) {
        final BasicX509Credential credential = new BasicX509Credential();
        credential.setEntityId(entityID);
        credential.setUsageType(usage);
        credential.setEntityCertificateChain(Collections.singletonList(certificate));

        return credential;
    }
}
