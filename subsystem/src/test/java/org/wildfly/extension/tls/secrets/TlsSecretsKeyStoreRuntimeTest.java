/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.extension.tls.secrets;

import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.ALLOW_RESOURCE_SERVICE_RESTART;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.FAILED;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.OPERATION_HEADERS;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.OUTCOME;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.SUBSYSTEM;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.SUCCESS;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Map;

import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.operations.common.Util;
import org.jboss.as.subsystem.test.AbstractSubsystemBaseTest;
import org.jboss.as.subsystem.test.AdditionalInitialization;
import org.jboss.as.subsystem.test.KernelServices;
import org.jboss.dmr.ModelNode;
import org.jboss.dmr.ValueExpression;
import org.jboss.msc.service.ServiceController;
import org.jboss.msc.service.ServiceName;
import org.junit.After;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class TlsSecretsKeyStoreRuntimeTest extends AbstractSubsystemBaseTest {

    private static final char[] KEY_PASSWORD = KubernetesTlsKeyStoreLoader.KEY_PASSWORD.toCharArray();
    private static final String EMPTY_SUBSYSTEM = "<subsystem xmlns=\"" + SubsystemParser_1_0.NAMESPACE + "\"/>";
    private static final PathAddress SUBSYSTEM_ADDRESS = PathAddress.pathAddress(SUBSYSTEM,
            TlsSecretsExtension.SUBSYSTEM_NAME);

    @Rule
    public TemporaryFolder temporaryFolder = new TemporaryFolder();

    private KernelServices services;

    public TlsSecretsKeyStoreRuntimeTest() {
        super(TlsSecretsExtension.SUBSYSTEM_NAME, new TlsSecretsExtension());
    }

    @Override
    protected String getSubsystemXml() throws IOException {
        return EMPTY_SUBSYSTEM;
    }

    @After
    public void shutdownServices() {
        if (services != null) {
            services.shutdown();
        }
    }

    @Test
    public void testRuntimeServicePublishesDefaultAliasAndIsRemoved() throws Exception {
        KubernetesTlsTestMaterial material = KubernetesTlsTestMaterial.create("RuntimeDefault");
        Path secretDirectory = material.writeTo(temporaryFolder.newFolder("runtime-default").toPath());
        services = createRuntimeServices();

        assertSuccessful(addKeyStore("server", secretDirectory.toString(), null));

        KeyStore keyStore = getKeyStore("server");
        assertEquals("PEM", keyStore.getType());
        assertKeyEntry(keyStore, "tls", material);

        ModelNode remove = Util.createRemoveOperation(keyStoreAddress("server"));
        allowResourceServiceRestart(remove);
        assertSuccessful(services.executeOperation(remove));
        services.getContainer().awaitStability();
        assertNull(services.getContainer().getService(serviceName("server")));
    }

    @Test
    public void testRuntimeServiceResolvesPathAndAliasExpressions() throws Exception {
        KubernetesTlsTestMaterial material = KubernetesTlsTestMaterial.create("RuntimeExpressions");
        Path secretDirectory = material.writeTo(temporaryFolder.newFolder("runtime-expressions").toPath());
        String pathProperty = "tls.secrets.runtime.test.path";
        String aliasProperty = "tls.secrets.runtime.test.alias";
        System.setProperty(pathProperty, secretDirectory.toString());
        System.setProperty(aliasProperty, "expression-alias");
        try {
            services = createRuntimeServices();
            ModelNode add = Util.createAddOperation(keyStoreAddress("expressions"));
            add.get(TlsSecretsKeyStoreDefinition.SECRET_PATH.getName())
                    .set(new ValueExpression("${" + pathProperty + "}"));
            add.get(TlsSecretsKeyStoreDefinition.ALIAS.getName())
                    .set(new ValueExpression("${" + aliasProperty + "}"));

            assertSuccessful(services.executeOperation(add));
            assertKeyEntry(getKeyStore("expressions"), "expression-alias", material);
        } finally {
            System.clearProperty(pathProperty);
            System.clearProperty(aliasProperty);
        }
    }

    @Test
    public void testWritingPathAndAliasRestartsOnlyTheKeyStoreService() throws Exception {
        KubernetesTlsTestMaterial firstMaterial = KubernetesTlsTestMaterial.create("RuntimeFirst");
        KubernetesTlsTestMaterial secondMaterial = KubernetesTlsTestMaterial.create("RuntimeSecond");
        Path firstDirectory = firstMaterial.writeTo(temporaryFolder.newFolder("runtime-first").toPath());
        Path secondDirectory = secondMaterial.writeTo(temporaryFolder.newFolder("runtime-second").toPath());
        services = createRuntimeServices();
        assertSuccessful(addKeyStore("replaceable", firstDirectory.toString(), null));

        KeyStore firstKeyStore = getKeyStore("replaceable");
        assertKeyEntry(firstKeyStore, "tls", firstMaterial);

        ModelNode writePath = Util.getWriteAttributeOperation(keyStoreAddress("replaceable"),
                TlsSecretsKeyStoreDefinition.SECRET_PATH.getName(), new ModelNode(secondDirectory.toString()));
        allowResourceServiceRestart(writePath);
        assertSuccessful(services.executeOperation(writePath));
        KeyStore secondKeyStore = getKeyStore("replaceable");
        assertNotSame(firstKeyStore, secondKeyStore);
        assertKeyEntry(secondKeyStore, "tls", secondMaterial);

        ModelNode writeAlias = Util.getWriteAttributeOperation(keyStoreAddress("replaceable"),
                TlsSecretsKeyStoreDefinition.ALIAS.getName(), new ModelNode("updated-alias"));
        allowResourceServiceRestart(writeAlias);
        assertSuccessful(services.executeOperation(writeAlias));
        KeyStore aliasedKeyStore = getKeyStore("replaceable");
        assertNotSame(secondKeyStore, aliasedKeyStore);
        assertKeyEntry(aliasedKeyStore, "updated-alias", secondMaterial);
    }

    @Test
    public void testFailedPathUpdateRestoresPreviousServiceAndModel() throws Exception {
        KubernetesTlsTestMaterial material = KubernetesTlsTestMaterial.create("Rollback");
        Path secretDirectory = material.writeTo(temporaryFolder.newFolder("rollback-valid").toPath());
        Path missingDirectory = temporaryFolder.getRoot().toPath().resolve("rollback-missing");
        services = createRuntimeServices();
        assertSuccessful(addKeyStore("rollback", secretDirectory.toString(), null));
        assertKeyEntry(getKeyStore("rollback"), "tls", material);

        ModelNode writePath = Util.getWriteAttributeOperation(keyStoreAddress("rollback"),
                TlsSecretsKeyStoreDefinition.SECRET_PATH.getName(), new ModelNode(missingDirectory.toString()));
        allowResourceServiceRestart(writePath);
        ModelNode response = services.executeOperation(writePath);

        assertEquals(response.toString(), FAILED, response.get(OUTCOME).asString());
        assertKeyEntry(getKeyStore("rollback"), "tls", material);
        ModelNode readPath = Util.getReadAttributeOperation(keyStoreAddress("rollback"),
                TlsSecretsKeyStoreDefinition.SECRET_PATH.getName());
        ModelNode readResponse = services.executeOperation(readPath);
        assertSuccessful(readResponse);
        assertEquals(secretDirectory.toString(), readResponse.get("result").asString());
    }

    @Test
    public void testFailedServiceStartRollsBackResourceAndCapability() throws Exception {
        Path missingDirectory = temporaryFolder.getRoot().toPath().resolve("missing-runtime-secret");
        services = createRuntimeServices();

        assertFailedAdd("missing", missingDirectory);
    }

    @Test
    public void testMalformedServiceStartRollsBackResourceAndCapability() throws Exception {
        KubernetesTlsTestMaterial material = KubernetesTlsTestMaterial.create("MalformedRuntime");
        Path secretDirectory = temporaryFolder.newFolder("malformed-runtime").toPath();
        Files.write(secretDirectory.resolve("tls.crt"),
                "-----BEGIN CERTIFICATE-----\nnot-base64\n-----END CERTIFICATE-----\n"
                        .getBytes(StandardCharsets.US_ASCII));
        Files.write(secretDirectory.resolve("tls.key"), material.tlsKey);
        services = createRuntimeServices();

        assertFailedAdd("malformed", secretDirectory);
    }

    @Test
    public void testMismatchedServiceStartRollsBackResourceAndCapability() throws Exception {
        KubernetesTlsTestMaterial certificateMaterial = KubernetesTlsTestMaterial.create("RuntimeCertificate");
        KubernetesTlsTestMaterial privateKeyMaterial = KubernetesTlsTestMaterial.create("RuntimePrivateKey");
        Path secretDirectory = temporaryFolder.newFolder("mismatched-runtime").toPath();
        Files.write(secretDirectory.resolve("tls.crt"), certificateMaterial.tlsCrt);
        Files.write(secretDirectory.resolve("tls.key"), privateKeyMaterial.tlsKey);
        services = createRuntimeServices();

        assertFailedAdd("mismatched", secretDirectory);
    }

    @Test
    public void testDuplicateElytronKeyStoreCapabilityIsRejected() throws Exception {
        String name = "duplicate";
        String capabilityName = TlsSecretsCapabilities.KEY_STORE_RUNTIME_CAPABILITY.getDynamicName(name);
        KubernetesTlsTestMaterial material = KubernetesTlsTestMaterial.create("DuplicateCapability");
        Path secretDirectory = material.writeTo(temporaryFolder.newFolder("duplicate-capability").toPath());
        services = createRuntimeServices(AdditionalInitialization.withCapabilities(
                Map.of(capabilityName, new Object())));

        ModelNode response = addKeyStore(name, secretDirectory.toString(), null);

        assertEquals(response.toString(), FAILED, response.get(OUTCOME).asString());
        assertTrue(response.toString(), response.toString().contains(capabilityName));
        assertNull(services.getContainer().getService(serviceName(name)));
    }

    private void assertFailedAdd(String name, Path secretDirectory) throws Exception {
        ModelNode response = addKeyStore(name, secretDirectory.toString(), null);

        assertEquals(response.toString(), FAILED, response.get(OUTCOME).asString());
        assertTrue(response.toString(), response.toString().contains(
                "Unable to start Kubernetes TLS KeyStore \\\"" + name + "\\\" from \\\"" + secretDirectory + "\\\""));
        services.getContainer().awaitStability();
        assertNull(services.getContainer().getService(serviceName(name)));
    }

    private KernelServices createRuntimeServices() throws Exception {
        return createRuntimeServices(new AdditionalInitialization());
    }

    private KernelServices createRuntimeServices(AdditionalInitialization initialization) throws Exception {
        KernelServices runtimeServices = createKernelServicesBuilder(initialization)
                .setSubsystemXml(EMPTY_SUBSYSTEM)
                .build();
        assertTrue(String.valueOf(runtimeServices.getBootError()), runtimeServices.isSuccessfulBoot());
        return runtimeServices;
    }

    private ModelNode addKeyStore(String name, String path, String alias) {
        ModelNode add = Util.createAddOperation(keyStoreAddress(name));
        add.get(TlsSecretsKeyStoreDefinition.SECRET_PATH.getName()).set(path);
        if (alias != null) {
            add.get(TlsSecretsKeyStoreDefinition.ALIAS.getName()).set(alias);
        }
        return services.executeOperation(add);
    }

    private KeyStore getKeyStore(String name) throws InterruptedException {
        services.getContainer().awaitStability();
        ServiceController<?> controller = services.getContainer().getService(serviceName(name));
        assertNotNull(controller);
        assertEquals(ServiceController.State.UP, controller.getState());
        return (KeyStore) controller.getValue();
    }

    private static void assertKeyEntry(KeyStore keyStore, String alias, KubernetesTlsTestMaterial material)
            throws Exception {
        assertEquals(1, keyStore.size());
        assertTrue(keyStore.containsAlias(alias));
        assertArrayEquals(material.keyPair.getPrivate().getEncoded(),
                keyStore.getKey(alias, KEY_PASSWORD).getEncoded());
        Certificate[] chain = keyStore.getCertificateChain(alias);
        assertEquals(2, chain.length);
        assertEquals(material.certificate, chain[0]);
        assertEquals(material.ca.getSelfSignedCertificate(), chain[1]);
    }

    private static PathAddress keyStoreAddress(String name) {
        return SUBSYSTEM_ADDRESS.append(TlsSecretsKeyStoreDefinition.KEY_STORE, name);
    }

    private static ServiceName serviceName(String name) {
        return TlsSecretsCapabilities.KEY_STORE_RUNTIME_CAPABILITY.getCapabilityServiceName(name);
    }

    private static void allowResourceServiceRestart(ModelNode operation) {
        operation.get(OPERATION_HEADERS, ALLOW_RESOURCE_SERVICE_RESTART).set(true);
    }

    private static void assertSuccessful(ModelNode response) {
        assertEquals(response.toString(), SUCCESS, response.get(OUTCOME).asString());
    }
}
