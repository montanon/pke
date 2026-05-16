Perform a pke-specific security audit on pending changes in the current branch.

1. Run `git diff dev...HEAD` (or `git diff` if on dev) to identify all changed files
2. Read the threat model at `/context/06_threat_model.md` and security assumptions at `/context/08_security_assumptions.md`
3. Audit every changed file against these pke-specific concerns:

**Cryptographic safety:**
- No custom crypto primitives — only platform standard libraries (CryptoKit, cryptography, PyNaCl)
- Keys never logged, serialized to plain text, or stored unencrypted at rest
- Snapshot encryption keys never stored on the backend
- Nonces/IVs never reused

**Evidence integrity:**
- Chain of custody metadata is immutable once committed
- Hash verification at every custody transfer
- No path where evidence payload can be modified after snapshot creation

**API security:**
- No endpoints that leak key material, evidence content, or custody internals
- Auth required on all non-public endpoints
- Input validation on all user-facing parameters

**Data handling:**
- No PII in logs
- No plaintext evidence in database columns
- Secrets loaded from environment, never hardcoded

Report findings as: CRITICAL / WARNING / INFO with file, line, and remediation.
