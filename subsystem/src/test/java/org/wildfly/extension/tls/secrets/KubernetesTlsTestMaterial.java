/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.extension.tls.secrets;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.wildfly.common.bytes.ByteStringBuilder;
import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.security.pem.Pem;
import org.wildfly.security.x500.cert.SelfSignedX509CertificateAndSigningKey;
import org.wildfly.security.x500.cert.X509CertificateBuilder;

final class KubernetesTlsTestMaterial {

    final SelfSignedX509CertificateAndSigningKey ca;
    final KeyPair keyPair;
    final X509Certificate certificate;
    final byte[] tlsKey;
    final byte[] tlsCrt;

    private KubernetesTlsTestMaterial(SelfSignedX509CertificateAndSigningKey ca, KeyPair keyPair,
            X509Certificate certificate, byte[] tlsKey, byte[] tlsCrt) {
        this.ca = ca;
        this.keyPair = keyPair;
        this.certificate = certificate;
        this.tlsKey = tlsKey;
        this.tlsCrt = tlsCrt;
    }

    static KubernetesTlsTestMaterial create(String commonName) throws Exception {
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

        return new KubernetesTlsTestMaterial(ca, keyPair, certificate, tlsKey.toArray(), tlsCrt.toArray());
    }

    Path writeTo(Path directory) throws IOException {
        Files.createDirectories(directory);
        Files.write(directory.resolve("tls.crt"), tlsCrt);
        Files.write(directory.resolve("tls.key"), tlsKey);
        return directory;
    }
}
