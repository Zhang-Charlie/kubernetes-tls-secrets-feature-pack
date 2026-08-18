# Week 9 Stretch-Goal Evaluation

Week 9 evaluated encrypted private keys and automatic Secret rotation. Neither
feature is included in the current subsystem. The implementation instead adds
edge-case coverage for projected Kubernetes volumes, EC keys, explicit aliases,
certificate-chain ordering, and failed management updates.

## Encrypted PEM private keys

The native Elytron `PEM` KeyStore accepts unencrypted PKCS #8, RSA PKCS #1, and
EC PKCS #8 private keys. It now rejects an `ENCRYPTED PRIVATE KEY` block with a
specific unsupported-feature message. Kubernetes `kubernetes.io/tls` Secrets
do not define a standard field containing a private-key passphrase.

Possible future designs are:

1. Add a credential-reference attribute to the `key-store` resource and use it
   only to decrypt the source PEM key.
2. Read a passphrase from an additional mounted Secret key.
3. Continue requiring an unencrypted key and rely on Secret mounting and file
   permissions for access control.

The first option is the preferred future direction because it uses WildFly's
credential model and avoids inventing a special passphrase filename. Its source
decryption credential must remain distinct from the fixed `kubernetes-tls`
compatibility password used for the in-memory KeyStore entry. Implementing it
also requires encrypted PKCS #8 parsing in Elytron, management-model additions,
credential lifecycle handling, and negative tests for wrong passwords and
unsupported encryption algorithms.

## Automatic file watching

Kubernetes projected Secret volumes use an atomic symlink layout. `tls.crt` and
`tls.key` point through `..data`, and an update replaces the `..data` symlink.
Watching only the two apparent files is therefore insufficient.

Possible future designs are:

1. Use `WatchService` on the mount directory, observe `..data` replacement,
   debounce related events, then reload the complete certificate/key pair.
2. Poll the resolved files periodically and reload when their identity or
   content changes.
3. Use a Kubernetes API informer rather than observing the mounted filesystem.
4. Expose an explicit management reload operation and let deployment tooling
   invoke it after rotation.

An explicit reload operation is the smallest useful next step. A later watcher
can call the same reload path. A production watcher must retain the last known
good identity after a failed reload, avoid publishing a certificate and key
from different Secret revisions, and refresh the dependent Elytron filtering
KeyStore, key-manager, and SSL context. Replacing only this subsystem's source
KeyStore would leave existing TLS contexts using old material.

Until that lifecycle contract exists, rotate certificates by restarting the
server or rolling the pod as described in the Kubernetes guide.
