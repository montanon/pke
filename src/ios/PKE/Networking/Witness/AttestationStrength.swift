// Shared bucket mapping for witness-count → attestation-strength labels
// (HLAM-50 #5 / HLAM-131). UI summaries and the client-side verification
// report read from this single source so "weak / medium / strong" means
// the same thing in every surface.
//
// Bucket thresholds are pinned by product:
//
//   * 0      → .none
//   * 1–2    → .low
//   * 3–9    → .medium
//   * 10+    → .high
//
// Negative input is treated defensively as "no attestations" — the
// witness count is always non-negative on the happy path, so a negative
// value indicates a caller bug we'd rather degrade gracefully than crash.

import Foundation

public enum AttestationStrength: String, CaseIterable, Sendable {
    case none
    case low
    case medium
    case high

    /// Map a raw witness count to its strength bucket. O(1), pure.
    public static func bucket(for count: Int) -> AttestationStrength {
        switch count {
        case ..<1:
            return .none
        case 1...2:
            return .low
        case 3...9:
            return .medium
        default:
            return .high
        }
    }
}
