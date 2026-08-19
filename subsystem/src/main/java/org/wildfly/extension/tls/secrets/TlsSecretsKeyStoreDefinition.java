/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.extension.tls.secrets;

import static org.wildfly.extension.tls.secrets.TlsSecretsCapabilities.KEY_STORE_RUNTIME_CAPABILITY;

import java.io.IOException;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.Collection;
import java.util.function.Consumer;

import org.jboss.as.controller.AbstractAddStepHandler;
import org.jboss.as.controller.AbstractWriteAttributeHandler.HandbackHolder;
import org.jboss.as.controller.AttributeDefinition;
import org.jboss.as.controller.CapabilityServiceBuilder;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.PersistentResourceDefinition;
import org.jboss.as.controller.RestartParentWriteAttributeHandler;
import org.jboss.as.controller.ServiceRemoveStepHandler;
import org.jboss.as.controller.SimpleAttributeDefinition;
import org.jboss.as.controller.SimpleAttributeDefinitionBuilder;
import org.jboss.as.controller.SimpleResourceDefinition;
import org.jboss.as.controller.operations.validation.StringLengthValidator;
import org.jboss.as.controller.registry.AttributeAccess;
import org.jboss.as.controller.registry.ManagementResourceRegistration;
import org.jboss.as.controller.registry.OperationEntry;
import org.jboss.dmr.ModelNode;
import org.jboss.dmr.ModelType;
import org.jboss.msc.service.ServiceController;
import org.jboss.msc.service.ServiceName;

final class TlsSecretsKeyStoreDefinition extends PersistentResourceDefinition {

    static final String KEY_STORE = "key-store";
    static final PathElement PATH = PathElement.pathElement(KEY_STORE);

    static final SimpleAttributeDefinition SECRET_PATH = SimpleAttributeDefinitionBuilder.create("path", ModelType.STRING, false)
            .setAllowExpression(true)
            .setValidator(new StringLengthValidator(1, false, true))
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .build();

    static final SimpleAttributeDefinition ALIAS = SimpleAttributeDefinitionBuilder.create("alias", ModelType.STRING, true)
            .setAllowExpression(true)
            .setDefaultValue(new ModelNode("tls"))
            .setValidator(new StringLengthValidator(1, true, true))
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .build();

    static final AttributeDefinition[] ATTRIBUTES = { SECRET_PATH, ALIAS };

    private static final KeyStoreAddHandler ADD = new KeyStoreAddHandler();
    private static final ServiceRemoveStepHandler REMOVE = new ServiceRemoveStepHandler(ADD);
    private static final KeyStoreWriteAttributeHandler WRITE = new KeyStoreWriteAttributeHandler();

    TlsSecretsKeyStoreDefinition() {
        super(new SimpleResourceDefinition.Parameters(PATH,
                TlsSecretsExtension.getResourceDescriptionResolver(TlsSecretsExtension.SUBSYSTEM_NAME, KEY_STORE))
                .setAddHandler(ADD)
                .setRemoveHandler(REMOVE)
                .setAddRestartLevel(OperationEntry.Flag.RESTART_RESOURCE_SERVICES)
                .setRemoveRestartLevel(OperationEntry.Flag.RESTART_RESOURCE_SERVICES)
                .setCapabilities(KEY_STORE_RUNTIME_CAPABILITY));
    }

    @Override
    public Collection<AttributeDefinition> getAttributes() {
        return Arrays.asList(ATTRIBUTES);
    }

    @Override
    public void registerAttributes(ManagementResourceRegistration resourceRegistration) {
        for (AttributeDefinition attribute : ATTRIBUTES) {
            resourceRegistration.registerReadWriteAttribute(attribute, null, WRITE);
        }
    }

    private static void installService(OperationContext context, ModelNode model) throws OperationFailedException {
        String name = context.getCurrentAddressValue();
        String secretPath = SECRET_PATH.resolveModelAttribute(context, model).asString();
        String alias = ALIAS.resolveModelAttribute(context, model).asString();

        CapabilityServiceBuilder<?> builder = context.getCapabilityServiceTarget().addCapability(KEY_STORE_RUNTIME_CAPABILITY);
        Consumer<KeyStore> keyStoreConsumer = builder.provides(KEY_STORE_RUNTIME_CAPABILITY);
        builder.setInstance(new TlsSecretsKeyStoreService(keyStoreConsumer, name, secretPath, alias));
        builder.setInitialMode(ServiceController.Mode.ACTIVE);
        builder.install();
    }

    private static ServiceName serviceName(PathAddress address) {
        return KEY_STORE_RUNTIME_CAPABILITY.fromBaseCapability(address.getLastElement().getValue())
                .getCapabilityServiceName(KeyStore.class);
    }

    private static final class KeyStoreAddHandler extends AbstractAddStepHandler {

        @Override
        protected void performRuntime(OperationContext context, ModelNode operation, ModelNode model)
                throws OperationFailedException {
            installService(context, model);
        }
    }

    private static final class KeyStoreWriteAttributeHandler extends RestartParentWriteAttributeHandler {

        private KeyStoreWriteAttributeHandler() {
            super(KEY_STORE);
        }

        @Override
        protected boolean applyUpdateToRuntime(OperationContext context, ModelNode operation, String attributeName,
                ModelNode resolvedValue, ModelNode currentValue, HandbackHolder<ModelNode> handbackHolder)
                throws OperationFailedException {
            ModelNode model = context.readResource(PathAddress.EMPTY_ADDRESS).getModel();
            String name = context.getCurrentAddressValue();
            String secretPath = SECRET_PATH.resolveModelAttribute(context, model).asString();
            String alias = ALIAS.resolveModelAttribute(context, model).asString();
            try {
                KubernetesTlsKeyStoreLoader.load(Path.of(secretPath), alias);
            } catch (GeneralSecurityException | IOException | InvalidPathException e) {
                throw new OperationFailedException(String.format(
                        "Unable to start Kubernetes TLS KeyStore \"%s\" from \"%s\"", name, secretPath), e);
            }
            return super.applyUpdateToRuntime(context, operation, attributeName, resolvedValue, currentValue,
                    handbackHolder);
        }

        @Override
        protected ServiceName getParentServiceName(PathAddress parentAddress) {
            return serviceName(parentAddress);
        }

        @Override
        protected void recreateParentService(OperationContext context, ModelNode parentModel)
                throws OperationFailedException {
            installService(context, parentModel);
        }
    }
}
