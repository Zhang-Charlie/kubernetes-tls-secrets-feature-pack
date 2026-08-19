/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.extension.tls.secrets;

import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.jboss.as.controller.AttributeDefinition;
import org.jboss.as.controller.ModelOnlyAddStepHandler;
import org.jboss.as.controller.ModelOnlyRemoveStepHandler;
import org.jboss.as.controller.PersistentResourceDefinition;
import org.jboss.as.controller.SimpleResourceDefinition;

/**
 * Root resource definition for the {@code tls-secrets} subsystem.
 */
public class TlsSecretsSubsystemDefinition extends PersistentResourceDefinition {

    public TlsSecretsSubsystemDefinition() {
        super(new SimpleResourceDefinition.Parameters(
                TlsSecretsExtension.SUBSYSTEM_PATH,
                TlsSecretsExtension.getResourceDescriptionResolver(TlsSecretsExtension.SUBSYSTEM_NAME))
                .setAddHandler(ModelOnlyAddStepHandler.INSTANCE)
                .setRemoveHandler(ModelOnlyRemoveStepHandler.INSTANCE));
    }

    @Override
    public Collection<AttributeDefinition> getAttributes() {
        return Collections.emptyList();
    }

    @Override
    protected List<? extends PersistentResourceDefinition> getChildren() {
        return List.of(new TlsSecretsKeyStoreDefinition());
    }
}
