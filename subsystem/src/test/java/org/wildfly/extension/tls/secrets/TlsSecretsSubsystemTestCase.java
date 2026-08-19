/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.extension.tls.secrets;

import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.FAILED;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.OUTCOME;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.RESULT;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.SUBSYSTEM;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.SUCCESS;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.io.IOException;

import javax.xml.stream.XMLStreamException;

import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.operations.common.Util;
import org.jboss.as.subsystem.test.AbstractSubsystemBaseTest;
import org.jboss.as.subsystem.test.AdditionalInitialization;
import org.jboss.as.subsystem.test.KernelServices;
import org.jboss.dmr.ModelNode;
import org.junit.Test;

public class TlsSecretsSubsystemTestCase extends AbstractSubsystemBaseTest {

    private static final PathAddress SUBSYSTEM_ADDRESS = PathAddress.pathAddress(SUBSYSTEM, TlsSecretsExtension.SUBSYSTEM_NAME);
    private static final String PATH_ATTRIBUTE = TlsSecretsKeyStoreDefinition.SECRET_PATH.getName();
    private static final String ALIAS_ATTRIBUTE = TlsSecretsKeyStoreDefinition.ALIAS.getName();

    public TlsSecretsSubsystemTestCase() {
        super(TlsSecretsExtension.SUBSYSTEM_NAME, new TlsSecretsExtension());
    }

    @Override
    protected String getSubsystemXml() throws IOException {
        return readResource("subsystem_1_0.xml");
    }

    @Override
    protected String getSubsystemXsdPath() {
        return "schema/wildfly-tls-secrets_1_0.xsd";
    }

    @Test
    public void testParsedModelContainsNamedKeyStores() throws Exception {
        KernelServices services = createKernelServicesBuilder(AdditionalInitialization.MANAGEMENT)
                .setSubsystemXml(getSubsystemXml())
                .build();
        assertTrue(String.valueOf(services.getBootError()), services.isSuccessfulBoot());

        ModelNode keyStores = modelAt(services.readWholeModel(), SUBSYSTEM_ADDRESS)
                .get(TlsSecretsKeyStoreDefinition.KEY_STORE);
        assertEquals("${env.SERVER_TLS_SECRET_DIR}", keyStores.get("server", PATH_ATTRIBUTE).asString());
        assertEquals("${server.tls.alias:server}", keyStores.get("server", ALIAS_ATTRIBUTE).asString());
        assertEquals("/var/run/secrets/management", keyStores.get("management", PATH_ATTRIBUTE).asString());
        assertEquals("tls", keyStores.get("management", ALIAS_ATTRIBUTE).asString());

        ModelNode readAlias = Util.getReadAttributeOperation(keyStoreAddress("management"), ALIAS_ATTRIBUTE);
        ModelNode response = services.executeOperation(readAlias);
        assertSuccessfulResult(response);
        assertEquals("tls", response.get(RESULT).asString());
    }

    @Test
    public void testEmptySubsystemRemainsValid() throws Exception {
        standardSubsystemTest("empty_subsystem_1_0.xml");
    }

    @Test
    public void testManagementOperations() throws Exception {
        KernelServices services = createEmptySubsystemServices();
        PathAddress address = keyStoreAddress("server");

        ModelNode add = Util.createAddOperation(address);
        add.get(PATH_ATTRIBUTE).set("/var/run/secrets/server");
        assertSuccessfulResult(services.executeOperation(add));
        assertEquals("/var/run/secrets/server",
                modelAt(services.readWholeModel(), address).get(PATH_ATTRIBUTE).asString());

        ModelNode writeAlias = Util.getWriteAttributeOperation(address, ALIAS_ATTRIBUTE, new ModelNode("certificate"));
        assertSuccessfulResult(services.executeOperation(writeAlias));
        assertEquals("certificate", modelAt(services.readWholeModel(), address).get(ALIAS_ATTRIBUTE).asString());

        assertSuccessfulResult(services.executeOperation(Util.createRemoveOperation(address)));
        assertFalse(modelAt(services.readWholeModel(), SUBSYSTEM_ADDRESS)
                .get(TlsSecretsKeyStoreDefinition.KEY_STORE).hasDefined("server"));
    }

    @Test
    public void testMissingPathIsRejected() throws Exception {
        KernelServices services = createEmptySubsystemServices();
        assertFailedResult(services.executeOperation(Util.createAddOperation(keyStoreAddress("missing-path"))));
    }

    @Test
    public void testEmptyPathIsRejected() throws Exception {
        KernelServices services = createEmptySubsystemServices();
        ModelNode add = Util.createAddOperation(keyStoreAddress("empty-path"));
        add.get(PATH_ATTRIBUTE).set("");
        assertFailedResult(services.executeOperation(add));
    }

    @Test
    public void testEmptyAliasIsRejected() throws Exception {
        KernelServices services = createEmptySubsystemServices();
        ModelNode add = Util.createAddOperation(keyStoreAddress("empty-alias"));
        add.get(PATH_ATTRIBUTE).set("/var/run/secrets/server");
        add.get(ALIAS_ATTRIBUTE).set("");
        assertFailedResult(services.executeOperation(add));
    }

    @Test
    public void testDuplicateKeyStoreNameIsRejected() throws Exception {
        String xml = "<subsystem xmlns=\"" + SubsystemParser_1_0.NAMESPACE + "\">"
                + "<key-store name=\"server\" path=\"/first\"/>"
                + "<key-store name=\"server\" path=\"/second\"/>"
                + "</subsystem>";

        OperationFailedException exception = assertThrows(OperationFailedException.class,
                () -> createKernelServicesBuilder(AdditionalInitialization.MANAGEMENT)
                .setSubsystemXml(xml)
                .build());
        assertTrue(exception.getFailureDescription().toString(),
                exception.getFailureDescription().asString().contains("Duplicate resource"));
    }

    @Test
    public void testUnknownAttributeIsRejected() {
        String xml = "<subsystem xmlns=\"" + SubsystemParser_1_0.NAMESPACE + "\">"
                + "<key-store name=\"server\" path=\"/secret\" unexpected=\"value\"/>"
                + "</subsystem>";
        assertThrows(XMLStreamException.class, () -> parse(xml));
    }

    @Test
    public void testUnknownElementIsRejected() {
        String xml = "<subsystem xmlns=\"" + SubsystemParser_1_0.NAMESPACE + "\">"
                + "<unknown/>"
                + "</subsystem>";
        assertThrows(XMLStreamException.class, () -> parse(xml));
    }

    private KernelServices createEmptySubsystemServices() throws Exception {
        KernelServices services = createKernelServicesBuilder(AdditionalInitialization.MANAGEMENT)
                .setSubsystemXml(readResource("empty_subsystem_1_0.xml"))
                .build();
        assertTrue(String.valueOf(services.getBootError()), services.isSuccessfulBoot());
        return services;
    }

    private static PathAddress keyStoreAddress(String name) {
        return SUBSYSTEM_ADDRESS.append(TlsSecretsKeyStoreDefinition.KEY_STORE, name);
    }

    private static ModelNode modelAt(ModelNode model, PathAddress address) {
        ModelNode current = model;
        for (PathElement element : address) {
            current = current.get(element.getKey(), element.getValue());
        }
        return current;
    }

    private static void assertSuccessfulResult(ModelNode response) {
        assertEquals(response.toString(), SUCCESS, response.get(OUTCOME).asString());
    }

    private static void assertFailedResult(ModelNode response) {
        assertEquals(response.toString(), FAILED, response.get(OUTCOME).asString());
    }
}
