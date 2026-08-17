/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.extension.tls.secrets;

import java.util.Arrays;
import java.util.Collection;

import org.jboss.as.controller.AttributeDefinition;
import org.jboss.as.controller.ModelOnlyAddStepHandler;
import org.jboss.as.controller.ModelOnlyRemoveStepHandler;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.PersistentResourceDefinition;
import org.jboss.as.controller.SimpleAttributeDefinition;
import org.jboss.as.controller.SimpleAttributeDefinitionBuilder;
import org.jboss.as.controller.SimpleResourceDefinition;
import org.jboss.as.controller.operations.validation.StringLengthValidator;
import org.jboss.dmr.ModelNode;
import org.jboss.dmr.ModelType;

final class TlsSecretsKeyStoreDefinition extends PersistentResourceDefinition {

    static final String KEY_STORE = "key-store";
    static final PathElement PATH = PathElement.pathElement(KEY_STORE);

    static final SimpleAttributeDefinition SECRET_PATH = SimpleAttributeDefinitionBuilder.create("path", ModelType.STRING, false)
            .setAllowExpression(true)
            .setValidator(new StringLengthValidator(1, false, true))
            .setRestartAllServices()
            .build();

    static final SimpleAttributeDefinition ALIAS = SimpleAttributeDefinitionBuilder.create("alias", ModelType.STRING, true)
            .setAllowExpression(true)
            .setDefaultValue(new ModelNode("tls"))
            .setValidator(new StringLengthValidator(1, true, true))
            .setRestartAllServices()
            .build();

    static final AttributeDefinition[] ATTRIBUTES = { SECRET_PATH, ALIAS };

    TlsSecretsKeyStoreDefinition() {
        super(new SimpleResourceDefinition.Parameters(PATH,
                TlsSecretsExtension.getResourceDescriptionResolver(TlsSecretsExtension.SUBSYSTEM_NAME, KEY_STORE))
                .setAddHandler(ModelOnlyAddStepHandler.INSTANCE)
                .setRemoveHandler(ModelOnlyRemoveStepHandler.INSTANCE));
    }

    @Override
    public Collection<AttributeDefinition> getAttributes() {
        return Arrays.asList(ATTRIBUTES);
    }
}
