// HLAM-160 — `MPCMessageFraming` tests.
//
// Four ACs are covered at three layers:
//
//   * AC #1 — encode: 4-byte BE length prefix + payload, sized correctly.
//   * AC #2 — decode + accumulator: oversized payloads rejected at the
//     1 MiB cap, valid frames reassembled.
//   * AC #3 — round-trip: `decode(encode(x)) == x` for representative
//     payload shapes (empty, small commitment-sized, attestation-sized,
//     exact 1 MiB cap).
//   * AC #4 — partial-read buffering: bytes arriving across multiple
//     `append(_:)` calls (including byte-by-byte) reassemble into the
//     correct frames; concatenated frames split correctly.

import Foundation
import XCTest
@testable import PKEWitness

final class MPCMessageFramingTests: XCTestCase {

    // MARK: AC #1 — encode writes a 4-byte BE length prefix + payload

    func test_encode_writesBigEndianLengthPrefix() throws {
        let payload = Data([0xDE, 0xAD, 0xBE, 0xEF])
        let frame = try MPCMessageFraming.encode(payload)

        XCTAssertEqual(frame.count, 4 + payload.count)
        XCTAssertEqual(Array(frame.prefix(4)), [0x00, 0x00, 0x00, 0x04])
        XCTAssertEqual(frame.suffix(from: 4), payload)
    }

    func test_encode_emptyPayload_writesZeroLengthPrefix() throws {
        let frame = try MPCMessageFraming.encode(Data())
        XCTAssertEqual(frame, Data([0x00, 0x00, 0x00, 0x00]))
    }

    func test_encode_largePayload_encodesLengthCorrectly() throws {
        let payload = Data(repeating: 0xAA, count: 0x1234)
        let frame = try MPCMessageFraming.encode(payload)
        XCTAssertEqual(Array(frame.prefix(4)), [0x00, 0x00, 0x12, 0x34])
    }

    // MARK: AC #1 — encode rejects oversized payloads

    func test_encode_rejectsPayloadOverOneMebibyte() {
        let oversized = Data(repeating: 0x00, count: MPCMessageFraming.maxPayloadSize + 1)
        XCTAssertThrowsError(try MPCMessageFraming.encode(oversized)) { error in
            guard case let .payloadTooLarge(observed, limit) = error as? MPCMessageFraming.FramingError else {
                XCTFail("expected .payloadTooLarge; got \(error)")
                return
            }
            XCTAssertEqual(observed, MPCMessageFraming.maxPayloadSize + 1)
            XCTAssertEqual(limit, MPCMessageFraming.maxPayloadSize)
        }
    }

    // MARK: AC #2 — decode reassembles a valid frame

    func test_decode_reassemblesValidFrame() throws {
        let payload = Data([0x01, 0x02, 0x03, 0x04, 0x05])
        let frame = try MPCMessageFraming.encode(payload)
        let decoded = try MPCMessageFraming.decode(frame)
        XCTAssertEqual(decoded, payload)
    }

    // MARK: AC #2 — decode rejects oversized declared length

    func test_decode_rejectsDeclaredLengthOverCap() {
        // Construct a frame that claims 2 MiB but has no payload bytes —
        // the limit check fires before any payload bytes are consumed,
        // so we don't have to allocate 2 MiB to test it.
        var frame = Data()
        let oversize = UInt32(MPCMessageFraming.maxPayloadSize + 1)
        frame.append(UInt8(truncatingIfNeeded: oversize >> 24))
        frame.append(UInt8(truncatingIfNeeded: oversize >> 16))
        frame.append(UInt8(truncatingIfNeeded: oversize >> 8))
        frame.append(UInt8(truncatingIfNeeded: oversize))

        XCTAssertThrowsError(try MPCMessageFraming.decode(frame)) { error in
            guard case let .declaredLengthExceedsLimit(claimed, limit) = error as? MPCMessageFraming.FramingError else {
                XCTFail("expected .declaredLengthExceedsLimit; got \(error)")
                return
            }
            XCTAssertEqual(claimed, MPCMessageFraming.maxPayloadSize + 1)
            XCTAssertEqual(limit, MPCMessageFraming.maxPayloadSize)
        }
    }

    // MARK: AC #2 — decode rejects truncated frames + length mismatches

    func test_decode_rejectsTruncatedFrame() {
        XCTAssertThrowsError(try MPCMessageFraming.decode(Data([0x00, 0x00]))) { error in
            guard case let .truncatedFrame(observed) = error as? MPCMessageFraming.FramingError else {
                XCTFail("expected .truncatedFrame; got \(error)")
                return
            }
            XCTAssertEqual(observed, 2)
        }
    }

    func test_decode_rejectsLengthMismatch() {
        // Length prefix claims 4 bytes but only 2 follow.
        let frame = Data([0x00, 0x00, 0x00, 0x04, 0x01, 0x02])
        XCTAssertThrowsError(try MPCMessageFraming.decode(frame)) { error in
            guard case let .lengthMismatch(declared, available) = error as? MPCMessageFraming.FramingError else {
                XCTFail("expected .lengthMismatch; got \(error)")
                return
            }
            XCTAssertEqual(declared, 4)
            XCTAssertEqual(available, 2)
        }
    }

    // MARK: AC #3 — byte-stable round-trip for representative shapes

    func test_roundTrip_emptyPayload() throws {
        try assertRoundTrip(Data())
    }

    func test_roundTrip_commitmentSizedPayload() throws {
        // ~600 bytes — roughly the canonical-bytes size of a commitment
        // with all metadata + signature.
        try assertRoundTrip(Data(repeating: 0xC0, count: 600))
    }

    func test_roundTrip_attestationSizedPayload() throws {
        // ~700 bytes — typical attestation size.
        try assertRoundTrip(Data(repeating: 0xA0, count: 700))
    }

    func test_roundTrip_atExactCap() throws {
        try assertRoundTrip(Data(repeating: 0xFF, count: MPCMessageFraming.maxPayloadSize))
    }

    // MARK: AC #4 — accumulator buffers partial reads

    func test_accumulator_assemblesFrameSplitAcrossAppends() throws {
        let accumulator = MPCFrameAccumulator()
        let payload = Data([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
        let frame = try MPCMessageFraming.encode(payload)

        // First chunk: only the length prefix
        let firstDrain = try accumulator.append(frame.prefix(4))
        XCTAssertTrue(firstDrain.isEmpty)
        XCTAssertEqual(accumulator.pendingByteCount, 4)

        // Second chunk: part of the payload
        let secondDrain = try accumulator.append(frame.subdata(in: 4 ..< 7))
        XCTAssertTrue(secondDrain.isEmpty)
        XCTAssertEqual(accumulator.pendingByteCount, 7)

        // Third chunk: the remaining payload bytes
        let thirdDrain = try accumulator.append(frame.suffix(from: 7))
        XCTAssertEqual(thirdDrain, [payload])
        XCTAssertEqual(accumulator.pendingByteCount, 0)
    }

    func test_accumulator_yieldsMultipleConcatenatedFrames() throws {
        let accumulator = MPCFrameAccumulator()
        let payloads = [
            Data([0x01]),
            Data([0x02, 0x03]),
            Data([0x04, 0x05, 0x06])
        ]
        var concatenated = Data()
        for payload in payloads {
            concatenated.append(try MPCMessageFraming.encode(payload))
        }

        let drained = try accumulator.append(concatenated)
        XCTAssertEqual(drained, payloads)
        XCTAssertEqual(accumulator.pendingByteCount, 0)
    }

    func test_accumulator_partialTrailingFrameKeptForNextAppend() throws {
        let accumulator = MPCFrameAccumulator()
        let first = Data([0xA1, 0xA2])
        let second = Data([0xB1, 0xB2, 0xB3])

        var combined = try MPCMessageFraming.encode(first)
        let secondFrame = try MPCMessageFraming.encode(second)
        // Append the second frame's prefix only — incomplete.
        combined.append(secondFrame.prefix(5))

        let firstDrain = try accumulator.append(combined)
        XCTAssertEqual(firstDrain, [first])
        XCTAssertEqual(accumulator.pendingByteCount, 5)

        let secondDrain = try accumulator.append(secondFrame.suffix(from: 5))
        XCTAssertEqual(secondDrain, [second])
        XCTAssertEqual(accumulator.pendingByteCount, 0)
    }

    func test_accumulator_byteByByteAppend_completesFrame() throws {
        let accumulator = MPCFrameAccumulator()
        let payload = Data([0xCA, 0xFE, 0xBA, 0xBE])
        let frame = try MPCMessageFraming.encode(payload)

        var observed: [Data] = []
        for byte in frame {
            observed.append(contentsOf: try accumulator.append(Data([byte])))
        }
        XCTAssertEqual(observed, [payload])
        XCTAssertEqual(accumulator.pendingByteCount, 0)
    }

    // MARK: AC #4 — accumulator rejects oversize declared length

    func test_accumulator_rejectsOversizeDeclaredLength() {
        let accumulator = MPCFrameAccumulator()
        let oversize = UInt32(MPCMessageFraming.maxPayloadSize + 1)
        let prefix = Data([
            UInt8(truncatingIfNeeded: oversize >> 24),
            UInt8(truncatingIfNeeded: oversize >> 16),
            UInt8(truncatingIfNeeded: oversize >> 8),
            UInt8(truncatingIfNeeded: oversize)
        ])
        XCTAssertThrowsError(try accumulator.append(prefix)) { error in
            guard case .declaredLengthExceedsLimit = error as? MPCMessageFraming.FramingError else {
                XCTFail("expected .declaredLengthExceedsLimit; got \(error)")
                return
            }
        }
    }

    // MARK: AC #4 — accumulator reset clears partial state

    func test_accumulator_resetClearsBuffer() throws {
        let accumulator = MPCFrameAccumulator()
        _ = try accumulator.append(Data([0x00, 0x00, 0x00, 0x10, 0xAA, 0xBB]))
        XCTAssertEqual(accumulator.pendingByteCount, 6)
        accumulator.reset()
        XCTAssertEqual(accumulator.pendingByteCount, 0)
    }
}

// MARK: - Helpers

private func assertRoundTrip(
    _ payload: Data,
    file: StaticString = #filePath,
    line: UInt = #line
) throws {
    let frame = try MPCMessageFraming.encode(payload)
    let decoded = try MPCMessageFraming.decode(frame)
    XCTAssertEqual(decoded, payload, file: file, line: line)
}
