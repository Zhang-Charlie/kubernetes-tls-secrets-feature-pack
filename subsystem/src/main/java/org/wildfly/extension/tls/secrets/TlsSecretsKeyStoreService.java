/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.extension.tls.secrets;

import java.io.IOException;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.function.Consumer;

import org.jboss.msc.service.Service;
import org.jboss.msc.service.StartContext;
import org.jboss.msc.service.StartException;
import org.jboss.msc.service.StopContext;

final class TlsSecretsKeyStoreService implements Service<KeyStore> {

    private final Consumer<KeyStore> keyStoreConsumer;
    private final String name;
    private final String secretPath;
    private final String alias;

    private volatile KeyStore keyStore;

    TlsSecretsKeyStoreService(Consumer<KeyStore> keyStoreConsumer, String name, String secretPath, String alias) {
        this.keyStoreConsumer = keyStoreConsumer;
        this.name = name;
        this.secretPath = secretPath;
        this.alias = alias;
    }

    @Override
    public void start(StartContext context) throws StartException {
        try {
            KeyStore loadedKeyStore = KubernetesTlsKeyStoreLoader.load(Path.of(secretPath), alias);
            keyStore = loadedKeyStore;
            keyStoreConsumer.accept(loadedKeyStore);
        } catch (GeneralSecurityException | IOException | InvalidPathException e) {
            throw new StartException(String.format(
                    "Unable to start Kubernetes TLS KeyStore \"%s\" from \"%s\"", name, secretPath), e);
        }
    }

    @Override
    public void stop(StopContext context) {
        keyStoreConsumer.accept(null);
        keyStore = null;
    }

    @Override
    public KeyStore getValue() {
        KeyStore current = keyStore;
        if (current == null) {
            throw new IllegalStateException("Kubernetes TLS KeyStore is not available");
        }
        return current;
    }
}
