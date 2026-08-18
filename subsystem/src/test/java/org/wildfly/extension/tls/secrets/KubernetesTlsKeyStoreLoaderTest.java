/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.extension.tls.secrets;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import org.junit.Assume;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class KubernetesTlsKeyStoreLoaderTest {

    private static final char[] KEY_PASSWORD = KubernetesTlsKeyStoreLoader.KEY_PASSWORD.toCharArray();

    @Rule
    public TemporaryFolder temporaryFolder = new TemporaryFolder();

    @Test
    public void testLoadKubernetesTlsSecretWithDefaultAlias() throws Exception {
        KubernetesTlsTestMaterial material = createKubernetesTlsMaterial("DefaultAlias");
        Path secretDirectory = createSecretDirectory("default-alias", material);

        KeyStore keyStore = KubernetesTlsKeyStoreLoader.load(secretDirectory);

        assertEquals("PEM", keyStore.getType());
        assertKeyEntry(keyStore, "tls", material);
    }

    @Test
    public void testLoadKubernetesTlsSecretWithExplicitAlias() throws Exception {
        KubernetesTlsTestMaterial material = createKubernetesTlsMaterial("ExplicitAlias");
        Path secretDirectory = createSecretDirectory("explicit-alias", material);

        KeyStore keyStore = KubernetesTlsKeyStoreLoader.load(secretDirectory, "server");

        assertKeyEntry(keyStore, "server", material);
    }

    @Test
    public void testLoadKubernetesProjectedSecretSymlinks() throws Exception {
        KubernetesTlsTestMaterial material = createKubernetesTlsMaterial("ProjectedVolume");
        Path secretDirectory = createDirectory("projected-volume");
        Path versionDirectory = Files.createDirectory(secretDirectory.resolve("..2026_08_18_09_00_00"));
        material.writeTo(versionDirectory);
        try {
            Files.createSymbolicLink(secretDirectory.resolve("..data"), versionDirectory.getFileName());
            Files.createSymbolicLink(secretDirectory.resolve("tls.crt"), Path.of("..data", "tls.crt"));
            Files.createSymbolicLink(secretDirectory.resolve("tls.key"), Path.of("..data", "tls.key"));
        } catch (IOException | UnsupportedOperationException e) {
            Assume.assumeNoException("Symbolic links are not supported by this test environment", e);
        }

        KeyStore keyStore = KubernetesTlsKeyStoreLoader.load(secretDirectory);

        assertKeyEntry(keyStore, "tls", material);
    }

    @Test
    public void testLoadAbsoluteAndRelativeDirectoryPathsContainingSpaces() throws Exception {
        KubernetesTlsTestMaterial material = createKubernetesTlsMaterial("PathForms");
        Path absoluteDirectory = createSecretDirectory("secret directory with spaces", material).toAbsolutePath();
        Path workingDirectory = Path.of("").toAbsolutePath();
        Path relativeDirectory = workingDirectory.relativize(absoluteDirectory);

        assertKeyEntry(KubernetesTlsKeyStoreLoader.load(absoluteDirectory), "tls", material);
        assertKeyEntry(KubernetesTlsKeyStoreLoader.load(relativeDirectory), "tls", material);
    }

    @Test
    public void testEncryptedPrivateKeyRetainsPathAndUnsupportedCause() throws Exception {
        KubernetesTlsTestMaterial material = createKubernetesTlsMaterial("EncryptedPrivateKey");
        Path secretDirectory = createSecretDirectory("encrypted-private-key", material);
        Path privateKeyPath = secretDirectory.resolve("tls.key");
        String encryptedLabel = new String(material.tlsKey, StandardCharsets.US_ASCII)
                .replace("PRIVATE KEY", "ENCRYPTED PRIVATE KEY");
        Files.write(privateKeyPath, encryptedLabel.getBytes(StandardCharsets.US_ASCII));

        IOException exception = assertThrows(IOException.class,
                () -> KubernetesTlsKeyStoreLoader.load(secretDirectory));

        assertEquals("Unable to load PEM private key file \"" + privateKeyPath + "\"", exception.getMessage());
        assertNotNull(exception.getCause());
        assertEquals("Encrypted PEM private keys are not supported", exception.getCause().getMessage());
    }

    @Test
    public void testMissingSecretDirectoryRetainsResolvedCertificatePath() throws Exception {
        Path secretDirectory = temporaryFolder.getRoot().toPath().resolve("missing-directory");
        Path certificatePath = secretDirectory.resolve("tls.crt");

        IOException exception = assertThrows(IOException.class,
                () -> KubernetesTlsKeyStoreLoader.load(secretDirectory));

        assertEquals("PEM certificate file does not exist: \"" + certificatePath + "\"", exception.getMessage());
    }

    @Test
    public void testMissingCertificateRetainsCertificatePath() throws Exception {
        KubernetesTlsTestMaterial material = createKubernetesTlsMaterial("MissingCertificate");
        Path secretDirectory = createDirectory("missing-certificate");
        Files.write(secretDirectory.resolve("tls.key"), material.tlsKey);
        Path certificatePath = secretDirectory.resolve("tls.crt");

        IOException exception = assertThrows(IOException.class,
                () -> KubernetesTlsKeyStoreLoader.load(secretDirectory));

        assertEquals("PEM certificate file does not exist: \"" + certificatePath + "\"", exception.getMessage());
    }

    @Test
    public void testMissingPrivateKeyRetainsPrivateKeyPath() throws Exception {
        KubernetesTlsTestMaterial material = createKubernetesTlsMaterial("MissingPrivateKey");
        Path secretDirectory = createDirectory("missing-private-key");
        Files.write(secretDirectory.resolve("tls.crt"), material.tlsCrt);
        Path privateKeyPath = secretDirectory.resolve("tls.key");

        IOException exception = assertThrows(IOException.class,
                () -> KubernetesTlsKeyStoreLoader.load(secretDirectory));

        assertEquals("PEM private key file does not exist: \"" + privateKeyPath + "\"", exception.getMessage());
    }

    @Test
    public void testMalformedCertificateRetainsPathAndCause() throws Exception {
        KubernetesTlsTestMaterial material = createKubernetesTlsMaterial("MalformedCertificate");
        Path secretDirectory = createDirectory("malformed-certificate");
        Path certificatePath = secretDirectory.resolve("tls.crt");
        Files.write(certificatePath, malformedPem("CERTIFICATE"));
        Files.write(secretDirectory.resolve("tls.key"), material.tlsKey);

        IOException exception = assertThrows(IOException.class,
                () -> KubernetesTlsKeyStoreLoader.load(secretDirectory));

        assertEquals("Unable to load PEM certificate file \"" + certificatePath + "\"", exception.getMessage());
        assertNotNull(exception.getCause());
        assertEquals("Unable to parse PEM content", exception.getCause().getMessage());
    }

    @Test
    public void testMalformedPrivateKeyRetainsPathAndCause() throws Exception {
        KubernetesTlsTestMaterial material = createKubernetesTlsMaterial("MalformedPrivateKey");
        Path secretDirectory = createDirectory("malformed-private-key");
        Path privateKeyPath = secretDirectory.resolve("tls.key");
        Files.write(secretDirectory.resolve("tls.crt"), material.tlsCrt);
        Files.write(privateKeyPath, malformedPem("PRIVATE KEY"));

        IOException exception = assertThrows(IOException.class,
                () -> KubernetesTlsKeyStoreLoader.load(secretDirectory));

        assertEquals("Unable to load PEM private key file \"" + privateKeyPath + "\"", exception.getMessage());
        assertNotNull(exception.getCause());
        assertEquals("Unable to parse PEM content", exception.getCause().getMessage());
    }

    @Test
    public void testMismatchedCertificateAndPrivateKeyPropagatesCertificateException() throws Exception {
        KubernetesTlsTestMaterial certificateMaterial = createKubernetesTlsMaterial("Certificate");
        KubernetesTlsTestMaterial privateKeyMaterial = createKubernetesTlsMaterial("PrivateKey");
        Path secretDirectory = createDirectory("mismatched");
        Files.write(secretDirectory.resolve("tls.crt"), certificateMaterial.tlsCrt);
        Files.write(secretDirectory.resolve("tls.key"), privateKeyMaterial.tlsKey);

        CertificateException exception = assertThrows(CertificateException.class,
                () -> KubernetesTlsKeyStoreLoader.load(secretDirectory));

        assertEquals("Private key does not match certificate public key", exception.getMessage());
    }

    private void assertKeyEntry(KeyStore keyStore, String alias, KubernetesTlsTestMaterial material) throws Exception {
        assertEquals(1, keyStore.size());
        assertTrue(keyStore.containsAlias(alias));
        assertArrayEquals(material.keyPair.getPrivate().getEncoded(), keyStore.getKey(alias, KEY_PASSWORD).getEncoded());
        Certificate[] chain = keyStore.getCertificateChain(alias);
        assertEquals(2, chain.length);
        assertEquals(material.certificate, chain[0]);
        assertEquals(material.ca.getSelfSignedCertificate(), chain[1]);
    }

    private Path createSecretDirectory(String name, KubernetesTlsTestMaterial material) throws IOException {
        Path secretDirectory = createDirectory(name);
        Files.write(secretDirectory.resolve("tls.crt"), material.tlsCrt);
        Files.write(secretDirectory.resolve("tls.key"), material.tlsKey);
        return secretDirectory;
    }

    private Path createDirectory(String name) throws IOException {
        return temporaryFolder.newFolder(name).toPath();
    }

    private KubernetesTlsTestMaterial createKubernetesTlsMaterial(String commonName) throws Exception {
        return KubernetesTlsTestMaterial.create(commonName);
    }

    private byte[] malformedPem(String type) {
        return ("-----BEGIN " + type + "-----\nnot-base64\n-----END " + type + "-----\n")
                .getBytes(StandardCharsets.US_ASCII);
    }

}
