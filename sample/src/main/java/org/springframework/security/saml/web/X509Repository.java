package org.springframework.security.saml.web;

import java.security.cert.X509Certificate;
import java.util.Set;

public interface X509Repository {
    X509Certificate get(String alias);
    void addPem(String alias, String pem);
    Set<String> getAvailableNames();
}
