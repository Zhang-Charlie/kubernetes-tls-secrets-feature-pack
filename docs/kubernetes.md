# Kubernetes Deployment

## Create the TLS Secret

Create a `kubernetes.io/tls` Secret from a PEM certificate chain and its
matching unencrypted private key:

```bash
kubectl create secret tls server-tls \
    --cert=server-chain.pem \
    --key=server-key.pem
```

In `server-chain.pem`, place the leaf certificate first and append issuer
certificates in chain order. The command stores the files under the standard
Secret keys `tls.crt` and `tls.key`.

The private key may use PKCS#8 `PRIVATE KEY`, PKCS#1 `RSA PRIVATE KEY`, or SEC1
named-curve `EC PRIVATE KEY` encoding.

## Mount the Secret

The container image must contain this feature pack and a WildFly/Elytron build
with native `PEM` KeyStore support. Stock WildFly 39 is not sufficient. The
following excerpt mounts the Secret read-only and supplies the directory path
through the expression used by the subsystem:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: tls-secrets-example
spec:
  replicas: 1
  selector:
    matchLabels:
      app: tls-secrets-example
  template:
    metadata:
      labels:
        app: tls-secrets-example
    spec:
      securityContext:
        fsGroup: 185
      containers:
        - name: wildfly
          image: registry.example.com/wildfly-tls-secrets:latest
          securityContext:
            runAsUser: 185
            runAsGroup: 185
            runAsNonRoot: true
          env:
            - name: SERVER_TLS_SECRET_DIR
              value: /etc/wildfly/tls/server
          ports:
            - name: https
              containerPort: 8443
          volumeMounts:
            - name: server-tls
              mountPath: /etc/wildfly/tls/server
              readOnly: true
      volumes:
        - name: server-tls
          secret:
            secretName: server-tls
            defaultMode: 0440
```

Configure the feature-pack subsystem with the same directory:

```xml
<subsystem xmlns="urn:wildfly:tls-secrets:1.0">
    <key-store name="server"
               path="${env.SERVER_TLS_SECRET_DIR}"
               alias="tls"/>
</subsystem>
```

Then add the Elytron filtering KeyStore, key-manager, and server SSL context
shown in the [configuration guide](configuration.md#elytron-tls-wiring).

The WildFly process user needs read access to both mounted files. A read-only
mount is expected; the subsystem never writes to the Secret directory.

## Verify the certificate

After an HTTPS listener has been configured to use the `kubernetes-tls` server
SSL context, forward its port locally:

```bash
kubectl port-forward deployment/tls-secrets-example 8443:8443
```

Inspect the certificate and chain presented by the server:

```bash
openssl s_client \
    -connect localhost:8443 \
    -servername server.example.com \
    -showcerts </dev/null
```

Verify that the first presented certificate is the leaf from `tls.crt` and
that subsequent certificates preserve the configured chain order. For a CA
issued certificate, pass the appropriate CA file with `-CAfile` to make
`openssl` validate the chain.

## Rotation

Kubernetes may update projected Secret files when the Secret changes, but this
version of the subsystem does not watch the filesystem. Restart the WildFly
server or roll the pod after rotating `server-tls`; otherwise the active
KeyStore and SSL context continue using the material loaded at startup.
