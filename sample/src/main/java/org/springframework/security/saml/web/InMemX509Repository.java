package org.springframework.security.saml.web;

import org.apache.commons.lang.StringUtils;
import org.opensaml.xml.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sun.security.provider.X509Factory;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class InMemX509Repository implements X509Repository {
    private static final Logger log = LoggerFactory.getLogger(InMemX509Repository.class);

    private final Map<String, String> keyStore;
    private final CertificateFactory certificateFactory;

    public InMemX509Repository(Map<String, String> keyStore) {
        this.keyStore = keyStore;
        try {
            this.certificateFactory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException ce) {
            throw new RuntimeException(ce);
        }
    }

    public InMemX509Repository() {
        this(new HashMap<>());
    }

    @Override
    public void addPem(final String alias, final String pem) {
        log.error("--------------  KEY REPO --------------- addPem");
        keyStore.put(alias, pem);
    }

    @Override
    public Set<String> getAvailableNames() {
        log.error("--------------  KEY REPO --------------- getAvailableNames");
        return Collections.unmodifiableSet(keyStore.keySet());
    }

    @Override
    public X509Certificate get(final String alias) {
        log.error("--------------  KEY REPO --------------- get");
        final String pem = keyStore.get(alias);
        if (StringUtils.isEmpty(pem)) {
            return null;
        }

        try {
            return (X509Certificate) certificateFactory.generateCertificate(
                    new ByteArrayInputStream(Base64.decode(
                            pem.replaceAll(X509Factory.BEGIN_CERT, "").replaceAll(X509Factory.END_CERT, "")
                    ))
            );
        } catch (CertificateException ce) {
            throw new RuntimeException(ce);
        }
    }
}
