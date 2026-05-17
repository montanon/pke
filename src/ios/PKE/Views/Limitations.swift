// Canonical caveat lists rendered by `LimitationsView`.
//
// `notMVP` is the iOS-side mirror of the `## Explicitly not MVP` bullets in
// `context/09_mvp_scope.md`. `LimitationsDocParityTests` reads the markdown
// at test time and asserts bullet-for-bullet equality, so any doc edit that
// is not mirrored here fails CI with a precise diff.
//
// `trustBoundaries` is the four-item caveat list pinned by AC#2 of HLAM-95.
// It is not present in the markdown today, so it has no parity guard — the
// test only asserts it has exactly four non-empty entries.

public enum Limitations {

    /// Verbatim bullets from `## Explicitly not MVP` in
    /// `context/09_mvp_scope.md`. Order matches the document.
    public static let notMVP: [String] = [
        "legal-grade certification,",
        "objective truth verification,",
        "full blockchain consensus,",
        "proof of work,",
        "proof of stake,",
        "token economics,",
        "robust Sybil resistance,",
        "full decentralized identity,",
        "full social network,",
        "public media feed,",
        "arbitrary encrypted file storage,",
        "camera roll import,",
        "bulk uploads,",
        "production trust-and-safety operations,",
        "guaranteed witness independence,",
        "guaranteed GPS authenticity."
    ]

    /// The four trust-boundary caveats called out in HLAM-95 AC#2.
    public static let trustBoundaries: [String] = [
        "no proof of plaintext authenticity",
        "witness independence is informational only",
        "no key rotation in MVP",
        "single-node backend"
    ]
}
