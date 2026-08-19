# WildFly Kubernetes TLS Secrets Feature Pack

This feature pack adds a `tls-secrets` subsystem that loads Kubernetes-style
TLS Secret mounts into WildFly. Each configured directory must contain separate
`tls.crt` and `tls.key` PEM files. The subsystem publishes the result through
WildFly's standard Elytron KeyStore capability namespace so it can be used by
an Elytron key-manager and server SSL context.

The implementation is currently preview work for ELY-3051. It supports initial
loading and management-driven service restarts; it does not watch mounted files
for certificate rotation.

## Build

The build requires JDK 17 or later and Maven:

```bash
mvn clean verify
```

The reactor contains the subsystem, shared Galleon metadata, feature pack, and
local Galleon anchor modules. Provision the `tls-secrets` Galleon layer to add
the extension and subsystem to a server.

## Compatibility

The feature requires a WildFly build or release that contains Elytron's native
`PEM` KeyStore and its separate-file load support. During development this
repository uses `wildfly-elytron` `2.10.0.CR1-SNAPSHOT` installed locally.

The development build is aligned with locally installed WildFly 41 and WildFly
Core 33 snapshots that contain the required Elytron work. Released stock
WildFly 39 contains Elytron 2.7.1 and cannot run a configured `tls-secrets`
KeyStore. Do not copy replacement Elytron JARs into an existing WildFly
installation.

## Guides

- [Subsystem and Elytron configuration](docs/configuration.md)
- [Kubernetes deployment](docs/kubernetes.md)
- [Week 9 stretch-goal evaluation](docs/week9-stretch-goals.md)
- [Development and verification](docs/development.md)
