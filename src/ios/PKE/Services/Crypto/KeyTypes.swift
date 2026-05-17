// Typed Swift wrappers around the two flavors of P-256 public key used by the
// PKE wire protocol, plus base64url-no-pad (de)serialization that matches the
// canonical encoding rule pinned in HLAM-3 / `context/16_canonical_encoding.md`.
//
// Both wrappers store the raw `x963Representation` form (65 bytes: `0x04 ‖ X ‖ Y`)
// — the same byte form that is base64url-encoded into the public-key fields on
// the wire (`05_data_model_public.md`).

import Crypto
import Foundation

public struct SigningPublicKey: Equatable, Sendable {
    public let underlying: P256.Signing.PublicKey

    public init(_ underlying: P256.Signing.PublicKey) {
        self.underlying = underlying
    }

    public init(base64url: String) throws {
        let raw = try KeyTypeCoding.decodeBase64URLNoPad(base64url, label: "SigningPublicKey")
        do {
            self.underlying = try P256.Signing.PublicKey(x963Representation: raw)
        } catch {
            throw CryptoError.encoding(
                reason: "SigningPublicKey x963 rejected (length \(raw.count))"
            )
        }
    }

    public var base64url: String {
        KeyTypeCoding.encodeBase64URLNoPad(underlying.x963Representation)
    }

    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.underlying.x963Representation == rhs.underlying.x963Representation
    }
}

public struct AgreementPublicKey: Equatable, Sendable {
    public let underlying: P256.KeyAgreement.PublicKey

    public init(_ underlying: P256.KeyAgreement.PublicKey) {
        self.underlying = underlying
    }

    public init(base64url: String) throws {
        let raw = try KeyTypeCoding.decodeBase64URLNoPad(base64url, label: "AgreementPublicKey")
        do {
            self.underlying = try P256.KeyAgreement.PublicKey(x963Representation: raw)
        } catch {
            throw CryptoError.encoding(
                reason: "AgreementPublicKey x963 rejected (length \(raw.count))"
            )
        }
    }

    public var base64url: String {
        KeyTypeCoding.encodeBase64URLNoPad(underlying.x963Representation)
    }

    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.underlying.x963Representation == rhs.underlying.x963Representation
    }
}

// MARK: - base64url-no-pad helpers
//
// Kept file-private (via the `internal` access of the enum + the fileprivate
// reach of these wrappers within the module). Promote to a shared
// `Base64URL.swift` only when a third caller appears.

enum KeyTypeCoding {
    static func decodeBase64URLNoPad(_ input: String, label: String) throws -> Data {
        // RFC 4648 §5 — strict base64url-no-pad: only `[A-Za-z0-9_-]`, no
        // padding, no whitespace. Foundation's `Data(base64Encoded:)` tolerates
        // some out-of-alphabet bytes inconsistently across platforms, so the
        // alphabet check runs first before any translation or decoding.
        // Specific-error fast paths first so callers get a helpful reason.
        if input.contains("=") {
            throw CryptoError.encoding(reason: "\(label) base64url must not contain padding")
        }
        if input.contains("+") || input.contains("/") {
            throw CryptoError.encoding(reason: "\(label) base64url must not contain '+' or '/'")
        }
        for scalar in input.unicodeScalars {
            switch scalar {
            case "A"..."Z", "a"..."z", "0"..."9", "-", "_":
                continue
            default:
                throw CryptoError.encoding(
                    reason: "\(label) base64url contains non-alphabet character"
                )
            }
        }
        var translated = input
        translated = translated.replacingOccurrences(of: "-", with: "+")
        translated = translated.replacingOccurrences(of: "_", with: "/")
        let remainder = translated.count % 4
        if remainder == 2 {
            translated += "=="
        } else if remainder == 3 {
            translated += "="
        } else if remainder == 1 {
            throw CryptoError.encoding(reason: "\(label) base64url length invalid")
        }
        guard let data = Data(base64Encoded: translated) else {
            throw CryptoError.encoding(reason: "\(label) base64url decode failed")
        }
        return data
    }

    static func encodeBase64URLNoPad(_ data: Data) -> String {
        var encoded = data.base64EncodedString()
        encoded = encoded.replacingOccurrences(of: "+", with: "-")
        encoded = encoded.replacingOccurrences(of: "/", with: "_")
        while encoded.hasSuffix("=") {
            encoded.removeLast()
        }
        return encoded
    }
}
