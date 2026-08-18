/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.extension.tls.secrets;

import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.SUBSYSTEM;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

import org.jboss.as.controller.Extension;
import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.capability.registry.RuntimeCapabilityRegistry;
import org.jboss.as.controller.extension.ExtensionRegistry;
import org.jboss.as.controller.extension.ExtensionRegistryType;
import org.jboss.as.controller.operations.common.Util;
import org.jboss.as.controller.registry.ManagementResourceRegistration;
import org.jboss.as.controller.registry.Resource;
import org.jboss.as.subsystem.test.AbstractSubsystemBaseTest;
import org.jboss.as.subsystem.test.AdditionalInitialization;
import org.jboss.as.subsystem.test.KernelServices;
import org.jboss.dmr.ModelNode;
import org.jboss.msc.service.ServiceController;
import org.jboss.msc.service.ServiceName;
import org.junit.After;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.wildfly.extension.elytron.ElytronExtension;

public class TlsSecretsElytronIntegrationTest extends AbstractSubsystemBaseTest {

    private static final String EMPTY_SUBSYSTEM = "<subsystem xmlns=\"" + SubsystemParser_1_0.NAMESPACE + "\"/>";
    private static final String RESOURCE_NAME = "server";
    private static final String FILTERING_KEY_STORE_NAME = "kubernetes-tls-store";
    private static final String ELYTRON_RESOURCE_NAME = "kubernetes-tls";
    private static final PathAddress TLS_SECRETS_SUBSYSTEM = PathAddress.pathAddress(SUBSYSTEM,
            TlsSecretsExtension.SUBSYSTEM_NAME);
    private static final PathAddress ELYTRON_SUBSYSTEM = PathAddress.pathAddress(SUBSYSTEM,
            ElytronExtension.SUBSYSTEM_NAME);

    @Rule
    public TemporaryFolder temporaryFolder = new TemporaryFolder();

    private KernelServices services;

    public TlsSecretsElytronIntegrationTest() {
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
    public void testSelfSignedCertificateWorksWithElytronSslContext() throws Exception {
        assertTlsHandshake(KubernetesTlsTestMaterial.createSelfSigned("Self Signed"), false);
    }

    @Test
    public void testCaIssuedCertificateChainWorksWithElytronSslContext() throws Exception {
        assertTlsHandshake(KubernetesTlsTestMaterial.create("CA Chain"), true);
    }

    private void assertTlsHandshake(KubernetesTlsTestMaterial material, boolean expectCaCertificate) throws Exception {
        Path secretDirectory = material.writeTo(temporaryFolder.newFolder().toPath());
        ModelNode addTlsSecrets = Util.createAddOperation(TLS_SECRETS_SUBSYSTEM);
        ModelNode addElytron = Util.createAddOperation(ELYTRON_SUBSYSTEM);
        ModelNode addKeyStore = Util.createAddOperation(TLS_SECRETS_SUBSYSTEM.append("key-store", RESOURCE_NAME));
        addKeyStore.get("path").set(secretDirectory.toString());
        ModelNode addFilteringKeyStore = Util.createAddOperation(ELYTRON_SUBSYSTEM.append("filtering-key-store",
                FILTERING_KEY_STORE_NAME));
        addFilteringKeyStore.get("key-store").set(RESOURCE_NAME);
        addFilteringKeyStore.get("alias-filter").set("ALL");
        ModelNode addKeyManager = Util.createAddOperation(ELYTRON_SUBSYSTEM.append("key-manager",
                ELYTRON_RESOURCE_NAME));
        addKeyManager.get("key-store").set(FILTERING_KEY_STORE_NAME);
        addKeyManager.get("credential-reference", "clear-text").set(KubernetesTlsKeyStoreLoader.KEY_PASSWORD);
        ModelNode addSslContext = Util.createAddOperation(ELYTRON_SUBSYSTEM.append("server-ssl-context",
                ELYTRON_RESOURCE_NAME));
        addSslContext.get("key-manager").set(ELYTRON_RESOURCE_NAME);

        services = createKernelServicesBuilder(new ElytronInitialization())
                .setBootOperations(List.of(addTlsSecrets, addElytron, addKeyStore, addFilteringKeyStore,
                        addKeyManager, addSslContext))
                .build();
        assertTrue(String.valueOf(services.getBootError()), services.isSuccessfulBoot());

        assertServiceUp(ServiceName.parse("org.wildfly.security.key-store." + RESOURCE_NAME), KeyStore.class);
        assertServiceUp(ServiceName.parse("org.wildfly.security.key-store." + FILTERING_KEY_STORE_NAME),
                KeyStore.class);
        SSLContext serverContext = assertServiceUp(
                ServiceName.parse("org.wildfly.security.ssl-context." + ELYTRON_RESOURCE_NAME), SSLContext.class);
        assertServiceUp(ServiceName.parse("org.wildfly.security.key-manager." + ELYTRON_RESOURCE_NAME),
                KeyManager.class);

        Certificate[] peerChain = handshake(serverContext, createClientContext(material));
        int expectedChainLength = expectCaCertificate ? 2 : 1;
        assertEquals(expectedChainLength, peerChain.length);
        assertEquals(material.certificate, peerChain[0]);
        if (expectCaCertificate) {
            assertEquals(material.ca.getSelfSignedCertificate(), peerChain[1]);
        }
    }

    private SSLContext createClientContext(KubernetesTlsTestMaterial material) throws Exception {
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null);
        X509Certificate trustedCertificate = material.ca.getSelfSignedCertificate();
        trustStore.setCertificateEntry("trusted", trustedCertificate);

        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(trustStore);
        SSLContext clientContext = SSLContext.getInstance("TLS");
        clientContext.init(null, trustManagerFactory.getTrustManagers(), null);
        return clientContext;
    }

    private static Certificate[] handshake(SSLContext serverContext, SSLContext clientContext) throws Exception {
        InetAddress loopback = InetAddress.getLoopbackAddress();
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try (SSLServerSocket serverSocket = (SSLServerSocket) serverContext.getServerSocketFactory()
                .createServerSocket(0, 1, loopback)) {
            serverSocket.setSoTimeout(10000);
            Future<Void> serverHandshake = executor.submit(() -> {
                try (SSLSocket socket = (SSLSocket) serverSocket.accept()) {
                    socket.setSoTimeout(10000);
                    socket.startHandshake();
                    return null;
                }
            });

            Certificate[] peerChain;
            try (SSLSocket clientSocket = (SSLSocket) clientContext.getSocketFactory()
                    .createSocket(loopback, serverSocket.getLocalPort())) {
                clientSocket.setSoTimeout(10000);
                clientSocket.startHandshake();
                peerChain = clientSocket.getSession().getPeerCertificates();
            }
            await(serverHandshake);
            return peerChain;
        } finally {
            executor.shutdownNow();
        }
    }

    private static void await(Future<Void> future) throws Exception {
        try {
            future.get();
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof Exception) {
                throw (Exception) cause;
            }
            throw e;
        }
    }

    private <T> T assertServiceUp(ServiceName serviceName, Class<T> type) throws InterruptedException {
        services.getContainer().awaitStability();
        ServiceController<?> controller = services.getContainer().getService(serviceName);
        assertNotNull(serviceName + "; installed security services: " + services.getContainer().getServiceNames().stream()
                .filter(name -> name.toString().startsWith("org.wildfly.security"))
                .toList(), controller);
        assertEquals(serviceName.toString(), ServiceController.State.UP, controller.getState());
        return type.cast(controller.getValue());
    }

    private static final class ElytronInitialization extends AdditionalInitialization {

        private final Extension extension = new ElytronExtension();

        @Override
        protected void initializeExtraSubystemsAndModel(ExtensionRegistry extensionRegistry, Resource rootResource,
                ManagementResourceRegistration rootRegistration, RuntimeCapabilityRegistry capabilityRegistry) {
            extension.initialize(extensionRegistry.getExtensionContext("org.wildfly.extension.elytron", rootRegistration,
                    ExtensionRegistryType.MASTER));
        }
    }
}
