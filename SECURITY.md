# Security policy

## Reporting a vulnerability

Report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/Seggys116/csync/security/advisories/new),
not in a public issue. Include the version, both platforms (host and guest), and a reproduction if you have one.

You can expect an acknowledgement within a few days. Fixes ship in a new release, and the advisory credits the
reporter unless they prefer otherwise.

## Supported versions

Only the latest release receives fixes.

## Threat model in brief

csync assumes an attacker on the LAN or VPN can read, inject and replay traffic and spoof mDNS.

* **Authenticated peers.** Every connection is a Noise handshake over X25519, ChaCha20-Poly1305 and BLAKE2s: `XX`
  for first pairing, `IK` for every later connection. csync refuses to load identity and peer files that other users can
  access. A host whose key changes is rejected; there is no silent re-pairing.
* **Pairing code.** First pairing needs the host to accept and the guest to confirm, after both users compare an
  8-character code derived from the handshake. Only one pairing is pending at a time, and it expires after 120 s.
  `csync host --no-pair` refuses new pairings.
* **Project-root confinement.** A paired guest can read and write the synced project and nothing else. Every path
  is validated and opened beneath the project root without following symlinks; `..` is rejected. Ignored files
  such as `.env` are never served, and `.git` is read-only to the guest.
* **Hostile input.** All peer data is length-bounded before decoding, and the decoders are fuzzed.

Of particular interest: anything that lets a guest escape the project root, read ignored files, or write `.git`;
anything that lets an unpaired peer get past the handshake; and the install script.

Out of scope: other local users beyond file permissions, and a malicious host attacking its guest beyond the
FUSE mount's own confinement.
