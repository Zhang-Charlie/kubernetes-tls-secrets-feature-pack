/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.extension.tls.secrets;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;

import javax.security.auth.x500.X500Principal;

import org.wildfly.common.bytes.ByteStringBuilder;
import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.security.asn1.DEREncoder;
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
        return create(commonName, "RSA", 2048);
    }

    static KubernetesTlsTestMaterial createEc(String commonName) throws Exception {
        return create(commonName, "EC", 256);
    }

    private static KubernetesTlsTestMaterial create(String commonName, String keyAlgorithm, int keySize)
            throws Exception {
        SelfSignedX509CertificateAndSigningKey ca = SelfSignedX509CertificateAndSigningKey.builder()
                .setDn(new X500Principal("CN=Test CA " + commonName))
                .setKeyAlgorithmName("RSA")
                .setSignatureAlgorithmName("SHA256withRSA")
                .setKeySize(2048)
                .addExtension(false, "BasicConstraints", "CA:true,pathlen:2147483647")
                .build();

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyAlgorithm);
        keyPairGenerator.initialize(keySize);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        X509Certificate certificate = new X509CertificateBuilder()
                .setIssuerDn(ca.getSelfSignedCertificate().getSubjectX500Principal())
                .setSubjectDn(new X500Principal("CN=Test " + commonName))
                .setSignatureAlgorithmName("SHA256withRSA")
                .setSigningKey(ca.getSigningKey())
                .setPublicKey(keyPair.getPublic())
                .build();

        ByteStringBuilder tlsKey = new ByteStringBuilder();
        if (keyPair.getPrivate() instanceof ECPrivateKey) {
            Pem.generatePemContent(tlsKey, "EC PRIVATE KEY",
                    ByteIterator.ofBytes(toSec1((ECPrivateKey) keyPair.getPrivate())));
        } else {
            Pem.generatePemContent(tlsKey, "PRIVATE KEY", ByteIterator.ofBytes(keyPair.getPrivate().getEncoded()));
        }

        ByteStringBuilder tlsCrt = new ByteStringBuilder();
        Pem.generatePemX509Certificate(tlsCrt, certificate);
        Pem.generatePemX509Certificate(tlsCrt, ca.getSelfSignedCertificate());

        return new KubernetesTlsTestMaterial(ca, keyPair, certificate, tlsKey.toArray(), tlsCrt.toArray());
    }

    static KubernetesTlsTestMaterial createSelfSigned(String commonName) {
        SelfSignedX509CertificateAndSigningKey certificateAndKey = SelfSignedX509CertificateAndSigningKey.builder()
                .setDn(new X500Principal("CN=Test " + commonName))
                .setKeyAlgorithmName("RSA")
                .setSignatureAlgorithmName("SHA256withRSA")
                .setKeySize(2048)
                .build();
        X509Certificate certificate = certificateAndKey.getSelfSignedCertificate();
        KeyPair keyPair = new KeyPair(certificate.getPublicKey(), certificateAndKey.getSigningKey());

        ByteStringBuilder tlsKey = new ByteStringBuilder();
        Pem.generatePemContent(tlsKey, "PRIVATE KEY", ByteIterator.ofBytes(keyPair.getPrivate().getEncoded()));

        ByteStringBuilder tlsCrt = new ByteStringBuilder();
        Pem.generatePemX509Certificate(tlsCrt, certificate);

        return new KubernetesTlsTestMaterial(certificateAndKey, keyPair, certificate, tlsKey.toArray(),
                tlsCrt.toArray());
    }

    private static byte[] toSec1(ECPrivateKey privateKey) {
        byte[] scalar = toFixedLength(privateKey.getS(), 32);
        DEREncoder encoder = new DEREncoder();
        encoder.startSequence();
        encoder.encodeInteger(1);
        encoder.encodeOctetString(scalar);
        encoder.startExplicit(0);
        encoder.encodeObjectIdentifier("1.2.840.10045.3.1.7");
        encoder.endExplicit();
        encoder.endSequence();
        return encoder.getEncoded();
    }

    private static byte[] toFixedLength(BigInteger value, int length) {
        byte[] encoded = value.toByteArray();
        byte[] result = new byte[length];
        int sourceOffset = Math.max(0, encoded.length - length);
        int copyLength = Math.min(encoded.length, length);
        System.arraycopy(encoded, sourceOffset, result, length - copyLength, copyLength);
        return result;
    }

    Path writeTo(Path directory) throws IOException {
        Files.createDirectories(directory);
        Files.write(directory.resolve("tls.crt"), tlsCrt);
        Files.write(directory.resolve("tls.key"), tlsKey);
        return directory;
    }
}
