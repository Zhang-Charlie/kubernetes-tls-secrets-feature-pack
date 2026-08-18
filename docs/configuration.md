# Subsystem and Elytron Configuration

## Secret directory

Each KeyStore resource points to one directory with this exact layout:

```text
/etc/wildfly/tls/server/
|-- tls.crt
`-- tls.key
```

`tls.crt` contains one or more PEM X.509 certificates. Put the leaf certificate
first, followed by its issuer certificates in chain order. `tls.key` contains
the matching unencrypted PEM private key. Encrypted private-key blocks are not
currently supported. The service rejects missing, malformed, or mismatched
material during startup and does not publish a partial KeyStore.

## Management model

The resource address is:

```text
/subsystem=tls-secrets/key-store=<name>
```

| Attribute | Required | Default | Behavior |
| --- | --- | --- | --- |
| `path` | Yes | None | Directory containing `tls.crt` and `tls.key`; expressions are allowed. |
| `alias` | No | `tls` | Alias assigned to the private-key entry; expressions are allowed. |

The resource name also becomes the dynamic capability name
`org.wildfly.security.key-store.<name>`. It shares Elytron's global KeyStore
namespace, so the name must not duplicate any other Elytron KeyStore provider.

XML configuration:

```xml
<subsystem xmlns="urn:wildfly:tls-secrets:1.0">
    <key-store name="server"
               path="${env.SERVER_TLS_SECRET_DIR}"
               alias="tls"/>
</subsystem>
```

Equivalent CLI configuration, after provisioning the `tls-secrets` layer:

```text
/subsystem=tls-secrets/key-store=server:add(path="${env.SERVER_TLS_SECRET_DIR}",alias=tls)
```

If the subsystem was not added by provisioning, add it before its child:

```text
/subsystem=tls-secrets:add
```

## Elytron TLS wiring

WildFly Core currently expects an Elytron-owned KeyStore service when creating
a key-manager. Use an Elytron `filtering-key-store` as the supported bridge from
the feature-pack capability, then configure the key-manager and server SSL
context:

```text
/subsystem=elytron/filtering-key-store=kubernetes-tls-store:add(key-store=server,alias-filter=ALL)
/subsystem=elytron/key-manager=kubernetes-tls:add(key-store=kubernetes-tls-store,credential-reference={clear-text="kubernetes-tls"})
/subsystem=elytron/server-ssl-context=kubernetes-tls:add(key-manager=kubernetes-tls)
```

The resulting runtime chain is:

```text
/subsystem=tls-secrets/key-store=server
    -> org.wildfly.security.key-store.server
    -> /subsystem=elytron/filtering-key-store=kubernetes-tls-store
    -> /subsystem=elytron/key-manager=kubernetes-tls
    -> /subsystem=elytron/server-ssl-context=kubernetes-tls
```

The `kubernetes-tls` clear-text value is a fixed compatibility password for the
in-memory KeyStore entry. It does not encrypt `tls.key` and is not a Kubernetes
credential. The source private key remains protected by the mounted file's
filesystem permissions.

An equivalent excerpt inside the Elytron subsystem is:

```xml
<tls>
    <key-stores>
        <filtering-key-store name="kubernetes-tls-store"
                             key-store="server"
                             alias-filter="ALL"/>
    </key-stores>
    <key-managers>
        <key-manager name="kubernetes-tls"
                     key-store="kubernetes-tls-store">
            <credential-reference clear-text="kubernetes-tls"/>
        </key-manager>
    </key-managers>
    <server-ssl-contexts>
        <server-ssl-context name="kubernetes-tls"
                            key-manager="kubernetes-tls"/>
    </server-ssl-contexts>
</tls>
```

Configure the server endpoint, such as an Undertow HTTPS listener, to reference
the resulting Elytron SSL context using its normal `ssl-context` attribute.
This feature pack supplies server identity; it does not create an Elytron trust
manager from the TLS Secret.

## Lifecycle and diagnostics

The KeyStore service starts eagerly. A missing directory, unreadable file,
invalid PEM document, certificate/key mismatch, or capability-name collision
therefore fails boot or the resource-add operation. Diagnostics identify the
KeyStore resource, the secret directory, and the certificate or key path that
failed.

Writing `path` or `alias` with resource-service restart allowed recreates only
that KeyStore service. An invalid replacement is rejected before the working
service is removed, so the previous model and KeyStore remain active. Removing
the management resource removes its capability. Changes made directly to
`tls.crt` or `tls.key` are not detected automatically; restart the server or pod
after mounted Secret content changes.

The underlying Elytron implementation is a read-only KeyStore type named
`PEM`. Official WildFly Elytron user-guide changes are intentionally deferred
until the required Elytron and WildFly versions are aligned.
