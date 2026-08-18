/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.extension.tls.secrets;

import java.security.KeyStore;

import org.jboss.as.controller.capability.RuntimeCapability;

final class TlsSecretsCapabilities {

    static final String KEY_STORE_CAPABILITY = "org.wildfly.security.key-store";

    static final RuntimeCapability<Void> KEY_STORE_RUNTIME_CAPABILITY = RuntimeCapability
            .Builder.of(KEY_STORE_CAPABILITY, true, KeyStore.class)
            .build();

    private TlsSecretsCapabilities() {
    }
}
