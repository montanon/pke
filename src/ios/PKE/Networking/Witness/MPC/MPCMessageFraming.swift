// HLAM-160 — length-prefixed framing for MPC payloads.
//
// Every payload sent through `MCSession.send(_:toPeers:with:)` is wrapped
// with a fixed 4-byte big-endian length prefix:
//
//     [length (4 bytes BE)][payload (length bytes)]
//
// MPC's `session(_:didReceive:fromPeer:)` delivers atomic `Data` blobs
// (the framework handles message boundaries on the wire), so for normal
// operation a single received blob == a single complete frame. The
// stateful `MPCFrameAccumulator` is still provided because:
//
//   * The wire format is self-describing: any tooling or test fixture
//     that concatenates frames (e.g. a multi-message round-trip golden
//     file) can be replayed without a separate length-tracking side
//     channel.
//   * Future transports under HLAM-50 (BLE chunking, HLAM-167) need
//     reassembly across multiple deliveries; sharing the framing
//     primitive avoids duplicating the size-bound check.
//
// Payload size cap is **1 MiB** (`1024 * 1024 = 1_048_576` bytes). Both
// the encoder and the decoder enforce it — an oversize claim in an
// inbound length prefix throws before any payload bytes are consumed,
// which prevents a malicious peer from forcing arbitrary buffer growth
// by quoting a large length and stalling.
//
// Cross-platform: this file imports only `Foundation` (no MPC, no
// CoreBluetooth) so it compiles unconditionally on every platform the
// PKE targets list — handy for sharing test fixtures with the backend.

import Foundation

public enum MPCMessageFraming {

    /// Maximum allowed payload size (1 MiB). Anything larger is
    /// rejected on both encode and decode paths.
    public static let maxPayloadSize = 1_048_576

    /// Fixed 4-byte big-endian length prefix at the front of every
    /// frame.
    public static let lengthPrefixSize = 4

    public enum FramingError: Error, Equatable, Sendable {

        /// Outbound payload exceeded `maxPayloadSize` on encode.
        case payloadTooLarge(observed: Int, limit: Int)

        /// Inbound length-prefix bytes claim a payload larger than the
        /// `maxPayloadSize` cap. Throws before any payload bytes are
        /// consumed.
        case declaredLengthExceedsLimit(claimed: Int, limit: Int)

        /// `decode(_:)` was handed a frame whose actual bytes do not
        /// match the length declared in its prefix. Stateless decode
        /// only — the accumulator buffers partial inputs instead of
        /// throwing.
        case lengthMismatch(declared: Int, available: Int)

        /// Frame had fewer than `lengthPrefixSize` bytes — cannot
        /// read the length prefix at all.
        case truncatedFrame(observed: Int)
    }

    // MARK: - Stateless encode/decode

    /// Wraps `payload` in a length-prefixed frame. Throws
    /// `.payloadTooLarge` if `payload` exceeds `maxPayloadSize`.
    public static func encode(_ payload: Data) throws -> Data {
        guard payload.count <= maxPayloadSize else {
            throw FramingError.payloadTooLarge(observed: payload.count, limit: maxPayloadSize)
        }
        var frame = Data(capacity: lengthPrefixSize + payload.count)
        let length = UInt32(payload.count)
        frame.append(UInt8(truncatingIfNeeded: length >> 24))
        frame.append(UInt8(truncatingIfNeeded: length >> 16))
        frame.append(UInt8(truncatingIfNeeded: length >> 8))
        frame.append(UInt8(truncatingIfNeeded: length))
        frame.append(payload)
        return frame
    }

    /// Decodes a single, complete frame. Throws `.truncatedFrame` if
    /// fewer than 4 bytes are supplied, `.declaredLengthExceedsLimit`
    /// for an oversized declared length, or `.lengthMismatch` if the
    /// frame's payload bytes do not match the declared length. Use
    /// `MPCFrameAccumulator` when bytes may arrive in chunks.
    public static func decode(_ frame: Data) throws -> Data {
        guard frame.count >= lengthPrefixSize else {
            throw FramingError.truncatedFrame(observed: frame.count)
        }
        let declared = readBigEndianLength(from: frame)
        guard declared <= maxPayloadSize else {
            throw FramingError.declaredLengthExceedsLimit(claimed: declared, limit: maxPayloadSize)
        }
        let available = frame.count - lengthPrefixSize
        guard available == declared else {
            throw FramingError.lengthMismatch(declared: declared, available: available)
        }
        return frame.subdata(in: lengthPrefixSize ..< lengthPrefixSize + declared)
    }

    /// Reads the 4-byte big-endian length prefix at the start of
    /// `bytes` and returns it as an `Int`. The caller is responsible
    /// for ensuring `bytes.count >= lengthPrefixSize`.
    fileprivate static func readBigEndianLength(from bytes: Data) -> Int {
        let start = bytes.startIndex
        let b0 = UInt32(bytes[start])
        let b1 = UInt32(bytes[start + 1])
        let b2 = UInt32(bytes[start + 2])
        let b3 = UInt32(bytes[start + 3])
        return Int((b0 << 24) | (b1 << 16) | (b2 << 8) | b3)
    }
}

// MARK: - Stateful accumulator

/// Buffers incoming bytes and yields complete payloads as they become
/// available. Tolerates partial reads (bytes arriving across multiple
/// `append(_:)` calls) and concatenated frames (multiple complete
/// frames in a single `append(_:)`).
///
/// Not thread-safe — callers are expected to drive a single accumulator
/// from a single isolation domain (the dispatcher/listener actors do
/// exactly that today).
public final class MPCFrameAccumulator {

    private var buffer: Data
    private let maxPayloadSize: Int

    public init(maxPayloadSize: Int = MPCMessageFraming.maxPayloadSize) {
        self.buffer = Data()
        self.maxPayloadSize = maxPayloadSize
    }

    /// Append `bytes` and drain every complete frame currently in the
    /// buffer. Throws `MPCMessageFraming.FramingError
    /// .declaredLengthExceedsLimit` if any frame's declared length
    /// would exceed the configured cap — the buffer is left in a
    /// poisoned state in that case (the caller should discard the
    /// accumulator and reconnect).
    public func append(_ bytes: Data) throws -> [Data] {
        buffer.append(bytes)
        var drained: [Data] = []
        while let payload = try extractNextFrame() {
            drained.append(payload)
        }
        return drained
    }

    /// Drop any buffered bytes — useful between sessions where a peer
    /// disconnect should not leak partial state into the next one.
    public func reset() {
        buffer.removeAll(keepingCapacity: false)
    }

    /// Number of bytes still pending in the buffer (not yet part of a
    /// complete frame). Exposed for diagnostics + tests.
    public var pendingByteCount: Int { buffer.count }

    private func extractNextFrame() throws -> Data? {
        guard buffer.count >= MPCMessageFraming.lengthPrefixSize else {
            return nil
        }
        let declared = MPCMessageFraming.readBigEndianLength(from: buffer)
        guard declared <= maxPayloadSize else {
            throw MPCMessageFraming.FramingError.declaredLengthExceedsLimit(
                claimed: declared,
                limit: maxPayloadSize
            )
        }
        let frameLength = MPCMessageFraming.lengthPrefixSize + declared
        guard buffer.count >= frameLength else {
            return nil
        }
        let payloadStart = buffer.startIndex + MPCMessageFraming.lengthPrefixSize
        let payload = buffer.subdata(in: payloadStart ..< payloadStart + declared)
        buffer.removeSubrange(buffer.startIndex ..< buffer.startIndex + frameLength)
        return payload
    }
}
