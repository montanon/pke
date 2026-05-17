// Stable application-tag strings for the two long-lived PKE identity keys.
// Values are pinned by HLAM-8 / HLAM-30 — changing them rotates every device.

#if canImport(Security)
public enum IdentityLabels {
    public static let signingTag = "com.pke.identity.signing"
    public static let agreementTag = "com.pke.identity.agreement"
}
#endif
