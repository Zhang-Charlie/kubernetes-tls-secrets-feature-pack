/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.extension.tls.secrets;

import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.Objects;

import org.wildfly.security.keystore.PemKeyStoreLoadParameter;
import org.wildfly.security.keystore.WildFlyElytronKeyStoreProvider;

final class KubernetesTlsKeyStoreLoader {

    private static final String CERTIFICATE_FILE_NAME = "tls.crt";
    private static final String PRIVATE_KEY_FILE_NAME = "tls.key";
    static final String KEY_PASSWORD = "kubernetes-tls";

    private KubernetesTlsKeyStoreLoader() {
    }

    static KeyStore load(Path secretDirectory) throws GeneralSecurityException, IOException {
        return load(secretDirectory, null);
    }

    static KeyStore load(Path secretDirectory, String alias) throws GeneralSecurityException, IOException {
        Objects.requireNonNull(secretDirectory, "secretDirectory");
        Path certificatePath = secretDirectory.resolve(CERTIFICATE_FILE_NAME);
        Path privateKeyPath = secretDirectory.resolve(PRIVATE_KEY_FILE_NAME);
        KeyStore keyStore = KeyStore.getInstance("PEM", WildFlyElytronKeyStoreProvider.getInstance());
        KeyStore.PasswordProtection protection = new KeyStore.PasswordProtection(KEY_PASSWORD.toCharArray());
        keyStore.load(new PemKeyStoreLoadParameter(certificatePath, privateKeyPath, alias, protection));
        return keyStore;
    }
}
