/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.extension.tls.secrets;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.util.concurrent.atomic.AtomicReference;

import org.jboss.msc.service.StartException;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class TlsSecretsKeyStoreServiceTest {

    @Rule
    public TemporaryFolder temporaryFolder = new TemporaryFolder();

    @Test
    public void testStopClearsPublishedKeyStore() throws Exception {
        KubernetesTlsTestMaterial material = KubernetesTlsTestMaterial.create("ServiceLifecycle");
        Path secretDirectory = material.writeTo(temporaryFolder.newFolder("service-lifecycle").toPath());
        AtomicReference<KeyStore> publishedKeyStore = new AtomicReference<>();
        TlsSecretsKeyStoreService service = new TlsSecretsKeyStoreService(publishedKeyStore::set,
                "server", secretDirectory.toString(), "tls");

        service.start(null);
        assertNotNull(publishedKeyStore.get());
        assertSame(publishedKeyStore.get(), service.getValue());

        service.stop(null);
        assertNull(publishedKeyStore.get());
        assertThrows(IllegalStateException.class, service::getValue);
    }

    @Test
    public void testMissingSecretRetainsContextAndDoesNotPublish() throws Exception {
        Path secretDirectory = temporaryFolder.getRoot().toPath().resolve("missing-service-secret");
        assertStartFailure(secretDirectory, IOException.class);
    }

    @Test
    public void testMalformedSecretRetainsContextAndDoesNotPublish() throws Exception {
        KubernetesTlsTestMaterial material = KubernetesTlsTestMaterial.create("MalformedService");
        Path secretDirectory = temporaryFolder.newFolder("malformed-service").toPath();
        Files.write(secretDirectory.resolve("tls.crt"),
                "-----BEGIN CERTIFICATE-----\nnot-base64\n-----END CERTIFICATE-----\n"
                        .getBytes(StandardCharsets.US_ASCII));
        Files.write(secretDirectory.resolve("tls.key"), material.tlsKey);

        StartException exception = assertStartFailure(secretDirectory, IOException.class);
        assertNotNull(exception.getCause().getCause());
    }

    @Test
    public void testMismatchedSecretRetainsContextAndDoesNotPublish() throws Exception {
        KubernetesTlsTestMaterial certificateMaterial = KubernetesTlsTestMaterial.create("ServiceCertificate");
        KubernetesTlsTestMaterial privateKeyMaterial = KubernetesTlsTestMaterial.create("ServicePrivateKey");
        Path secretDirectory = temporaryFolder.newFolder("mismatched-service").toPath();
        Files.write(secretDirectory.resolve("tls.crt"), certificateMaterial.tlsCrt);
        Files.write(secretDirectory.resolve("tls.key"), privateKeyMaterial.tlsKey);

        assertStartFailure(secretDirectory, CertificateException.class);
    }

    private StartException assertStartFailure(Path secretDirectory, Class<? extends Exception> causeType) {
        AtomicReference<KeyStore> publishedKeyStore = new AtomicReference<>();
        TlsSecretsKeyStoreService service = new TlsSecretsKeyStoreService(publishedKeyStore::set,
                "server", secretDirectory.toString(), "tls");

        StartException exception = assertThrows(StartException.class, () -> service.start(null));

        assertEquals("Unable to start Kubernetes TLS KeyStore \"server\" from \"" + secretDirectory + "\"",
                exception.getMessage());
        assertTrue(exception.toString(), causeType.isInstance(exception.getCause()));
        assertNull(publishedKeyStore.get());
        assertThrows(IllegalStateException.class, service::getValue);
        return exception;
    }
}
