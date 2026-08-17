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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.wildfly.common.bytes.ByteStringBuilder;
import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.security.pem.Pem;
import org.wildfly.security.x500.cert.SelfSignedX509CertificateAndSigningKey;
import org.wildfly.security.x500.cert.X509CertificateBuilder;

public class KubernetesTlsKeyStoreLoaderTest {

    private static final char[] EMPTY_PASSWORD = new char[0];

    @Rule
    public TemporaryFolder temporaryFolder = new TemporaryFolder();

    @Test
    public void testLoadKubernetesTlsSecretWithDefaultAlias() throws Exception {
        KubernetesTlsMaterial material = createKubernetesTlsMaterial("DefaultAlias");
        Path secretDirectory = createSecretDirectory("default-alias", material);

        KeyStore keyStore = KubernetesTlsKeyStoreLoader.load(secretDirectory);

        assertEquals("PEM", keyStore.getType());
        assertKeyEntry(keyStore, "tls", material);
    }

    @Test
    public void testLoadKubernetesTlsSecretWithExplicitAlias() throws Exception {
        KubernetesTlsMaterial material = createKubernetesTlsMaterial("ExplicitAlias");
        Path secretDirectory = createSecretDirectory("explicit-alias", material);

        KeyStore keyStore = KubernetesTlsKeyStoreLoader.load(secretDirectory, "server");

        assertKeyEntry(keyStore, "server", material);
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
        KubernetesTlsMaterial material = createKubernetesTlsMaterial("MissingCertificate");
        Path secretDirectory = createDirectory("missing-certificate");
        Files.write(secretDirectory.resolve("tls.key"), material.tlsKey);
        Path certificatePath = secretDirectory.resolve("tls.crt");

        IOException exception = assertThrows(IOException.class,
                () -> KubernetesTlsKeyStoreLoader.load(secretDirectory));

        assertEquals("PEM certificate file does not exist: \"" + certificatePath + "\"", exception.getMessage());
    }

    @Test
    public void testMissingPrivateKeyRetainsPrivateKeyPath() throws Exception {
        KubernetesTlsMaterial material = createKubernetesTlsMaterial("MissingPrivateKey");
        Path secretDirectory = createDirectory("missing-private-key");
        Files.write(secretDirectory.resolve("tls.crt"), material.tlsCrt);
        Path privateKeyPath = secretDirectory.resolve("tls.key");

        IOException exception = assertThrows(IOException.class,
                () -> KubernetesTlsKeyStoreLoader.load(secretDirectory));

        assertEquals("PEM private key file does not exist: \"" + privateKeyPath + "\"", exception.getMessage());
    }

    @Test
    public void testMalformedCertificateRetainsPathAndCause() throws Exception {
        KubernetesTlsMaterial material = createKubernetesTlsMaterial("MalformedCertificate");
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
        KubernetesTlsMaterial material = createKubernetesTlsMaterial("MalformedPrivateKey");
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
        KubernetesTlsMaterial certificateMaterial = createKubernetesTlsMaterial("Certificate");
        KubernetesTlsMaterial privateKeyMaterial = createKubernetesTlsMaterial("PrivateKey");
        Path secretDirectory = createDirectory("mismatched");
        Files.write(secretDirectory.resolve("tls.crt"), certificateMaterial.tlsCrt);
        Files.write(secretDirectory.resolve("tls.key"), privateKeyMaterial.tlsKey);

        CertificateException exception = assertThrows(CertificateException.class,
                () -> KubernetesTlsKeyStoreLoader.load(secretDirectory));

        assertEquals("Private key does not match certificate public key", exception.getMessage());
    }

    private void assertKeyEntry(KeyStore keyStore, String alias, KubernetesTlsMaterial material) throws Exception {
        assertEquals(1, keyStore.size());
        assertTrue(keyStore.containsAlias(alias));
        assertArrayEquals(material.keyPair.getPrivate().getEncoded(), keyStore.getKey(alias, EMPTY_PASSWORD).getEncoded());
        Certificate[] chain = keyStore.getCertificateChain(alias);
        assertEquals(2, chain.length);
        assertEquals(material.certificate, chain[0]);
        assertEquals(material.ca.getSelfSignedCertificate(), chain[1]);
    }

    private Path createSecretDirectory(String name, KubernetesTlsMaterial material) throws IOException {
        Path secretDirectory = createDirectory(name);
        Files.write(secretDirectory.resolve("tls.crt"), material.tlsCrt);
        Files.write(secretDirectory.resolve("tls.key"), material.tlsKey);
        return secretDirectory;
    }

    private Path createDirectory(String name) throws IOException {
        return temporaryFolder.newFolder(name).toPath();
    }

    private KubernetesTlsMaterial createKubernetesTlsMaterial(String commonName) throws Exception {
        SelfSignedX509CertificateAndSigningKey ca = SelfSignedX509CertificateAndSigningKey.builder()
                .setDn(new X500Principal("CN=Test CA " + commonName))
                .setKeyAlgorithmName("RSA")
                .setSignatureAlgorithmName("SHA256withRSA")
                .setKeySize(2048)
                .build();

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        X509Certificate certificate = new X509CertificateBuilder()
                .setIssuerDn(ca.getSelfSignedCertificate().getSubjectX500Principal())
                .setSubjectDn(new X500Principal("CN=Test " + commonName))
                .setSignatureAlgorithmName("SHA256withRSA")
                .setSigningKey(ca.getSigningKey())
                .setPublicKey(keyPair.getPublic())
                .build();

        ByteStringBuilder tlsKey = new ByteStringBuilder();
        Pem.generatePemContent(tlsKey, "PRIVATE KEY", ByteIterator.ofBytes(keyPair.getPrivate().getEncoded()));

        ByteStringBuilder tlsCrt = new ByteStringBuilder();
        Pem.generatePemX509Certificate(tlsCrt, certificate);
        Pem.generatePemX509Certificate(tlsCrt, ca.getSelfSignedCertificate());

        return new KubernetesTlsMaterial(ca, keyPair, certificate, tlsKey.toArray(), tlsCrt.toArray());
    }

    private byte[] malformedPem(String type) {
        return ("-----BEGIN " + type + "-----\nnot-base64\n-----END " + type + "-----\n")
                .getBytes(StandardCharsets.US_ASCII);
    }

    private static final class KubernetesTlsMaterial {

        private final SelfSignedX509CertificateAndSigningKey ca;
        private final KeyPair keyPair;
        private final X509Certificate certificate;
        private final byte[] tlsKey;
        private final byte[] tlsCrt;

        private KubernetesTlsMaterial(SelfSignedX509CertificateAndSigningKey ca, KeyPair keyPair,
                X509Certificate certificate, byte[] tlsKey, byte[] tlsCrt) {
            this.ca = ca;
            this.keyPair = keyPair;
            this.certificate = certificate;
            this.tlsKey = tlsKey;
            this.tlsCrt = tlsCrt;
        }
    }
}
