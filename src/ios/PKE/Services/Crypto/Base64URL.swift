import Foundation

public enum Base64URL {
    public static func encode(_ data: Data) -> String {
        let standard = data.base64EncodedString()
        var out = ""
        out.reserveCapacity(standard.count)
        for scalar in standard.unicodeScalars {
            switch scalar {
            case "+":
                out.append("-")
            case "/":
                out.append("_")
            case "=":
                continue
            default:
                out.unicodeScalars.append(scalar)
            }
        }
        return out
    }

    public static func decode(_ string: String) throws -> Data {
        try validateURLSafe(string)
        var translated = ""
        translated.reserveCapacity(string.count)
        for scalar in string.unicodeScalars {
            switch scalar {
            case "-":
                translated.append("+")
            case "_":
                translated.append("/")
            default:
                translated.unicodeScalars.append(scalar)
            }
        }
        let padLength = (4 - translated.count % 4) % 4
        if padLength == 1 {
            throw CryptoError.encoding(reason: "invalid length mod 4")
        }
        translated.append(String(repeating: "=", count: padLength))
        guard let decoded = Data(base64Encoded: translated) else {
            throw CryptoError.encoding(reason: "base64 decode failed")
        }
        return decoded
    }

    private static func validateURLSafe(_ string: String) throws {
        for (offset, scalar) in string.unicodeScalars.enumerated() {
            if !isURLSafeAlphabet(scalar) {
                throw CryptoError.encoding(
                    reason: "invalid character at index \(offset)"
                )
            }
        }
    }

    private static func isURLSafeAlphabet(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar {
        case "A"..."Z", "a"..."z", "0"..."9", "-", "_":
            return true
        default:
            return false
        }
    }
}
