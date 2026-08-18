# Development and Verification

## Dependency order

The native Elytron `PEM` KeyStore must be built and installed before this
feature pack. From the Elytron repository, run:

```bash
mvn -pl keystore -am test
mvn -pl keystore -am install -DskipTests
```

The feature-pack build then resolves `wildfly-elytron-keystore`
`2.10.0.CR1-SNAPSHOT` from the local Maven repository. Do not copy Elytron JARs
into a WildFly installation; all Elytron modules in a server must come from one
aligned WildFly build.

## Automated verification

Run the focused subsystem tests while developing:

```bash
mvn -pl subsystem test
```

They cover PEM loading, projected Kubernetes Secret symlinks, management-model
parsing, capability lifecycle, failed-update rollback, and loopback TLS
handshakes through an Elytron key-manager and server SSL context.

Before publishing a branch, run the complete reactor and whitespace checks:

```bash
mvn verify
git diff --check
```

The complete reactor validates the subsystem JAR, Galleon shared content,
feature pack, and local anchor. Two tests inherited from WildFly's subsystem
test framework may report as skipped; the project-specific tests must not skip.

## Provisioned-server verification

The generated server under `feature-pack/target/wildfly` is based on stock
WildFly 39 and is useful for packaging and empty-subsystem boot checks. Its
Elytron modules contain `wildfly-elytron-keystore` `2.7.1.Final`, so it cannot
run a configured Kubernetes TLS KeyStore.

A configured-server test requires WildFly Core and WildFly feature packs built
against the same Elytron snapshot. Provision this feature pack against those
locally installed feature packs, then verify:

1. The server boots with `/subsystem=tls-secrets/key-store=server` configured.
2. The filtering KeyStore, key-manager, and server SSL context reach `UP`.
3. An Undertow HTTPS listener completes a TLS handshake.
4. The server presents the leaf certificate followed by the configured issuer
   chain.
5. A rejected `path` update leaves the previous KeyStore and model active.

The automated loopback handshake test is the authoritative integration test
until an aligned WildFly release can be used directly by this build.
