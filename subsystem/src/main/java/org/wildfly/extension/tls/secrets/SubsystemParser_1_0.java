/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.extension.tls.secrets;

import static org.jboss.as.controller.PersistentResourceXMLDescription.builder;

import org.jboss.as.controller.PersistentResourceXMLDescription;
import org.jboss.as.controller.PersistentResourceXMLParser;

/**
 * Parser for the {@code tls-secrets} subsystem.
 */
public class SubsystemParser_1_0 extends PersistentResourceXMLParser {

    public static final String NAMESPACE = "urn:wildfly:tls-secrets:1.0";

    private static final PersistentResourceXMLDescription xmlDescription = builder(TlsSecretsExtension.SUBSYSTEM_PATH, NAMESPACE)
            .addChild(builder(TlsSecretsKeyStoreDefinition.PATH)
                    .addAttributes(TlsSecretsKeyStoreDefinition.ATTRIBUTES))
            .build();

    @Override
    public PersistentResourceXMLDescription getParserDescription() {
        return xmlDescription;
    }
}
