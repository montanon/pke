// Display helpers for the device signing public key.
//
// `display(rawPublicKey:)` produces the abbreviated SHA-256 fingerprint shown
// in the Settings screen — first 8 hex chars + "⋯" + last 8 chars of the
// 64-char lowercase hex digest. `fullHex(rawPublicKey:)` returns the
// lowercase hex of the raw key bytes themselves, which the copy button
// writes verbatim to the pasteboard per HLAM-95 AC#3.

import Foundation
import PKECrypto

public enum Fingerprint {

    private static let emDash = "—"
    private static let middleEllipsis = "\u{22EF}"

    /// SHA-256(rawPublicKey) → lowercase hex → `first8 + "⋯" + last8`.
    /// Returns `"—"` when the input is empty.
    public static func display(rawPublicKey: Data) -> String {
        guard !rawPublicKey.isEmpty else { return emDash }
        let hex = hexLowercase(Hashing.sha256(rawPublicKey))
        let head = hex.prefix(8)
        let tail = hex.suffix(8)
        return "\(head)\(middleEllipsis)\(tail)"
    }

    /// Lowercase hex of the raw key bytes. Returns `""` for empty input.
    public static func fullHex(rawPublicKey: Data) -> String {
        hexLowercase(rawPublicKey)
    }

    private static func hexLowercase(_ data: Data) -> String {
        var out = String()
        out.reserveCapacity(data.count * 2)
        for byte in data {
            let high = Int(byte >> 4)
            let low = Int(byte & 0x0F)
            out.append(Self.hexDigits[high])
            out.append(Self.hexDigits[low])
        }
        return out
    }

    private static let hexDigits: [Character] = [
        "0", "1", "2", "3", "4", "5", "6", "7",
        "8", "9", "a", "b", "c", "d", "e", "f"
    ]
}
