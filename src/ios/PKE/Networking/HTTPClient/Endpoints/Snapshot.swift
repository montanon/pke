// HLAM-151 — Snapshot endpoints + blob upload/download.
//
// Public extension on `PKEHTTPClient` that exposes the four operations the
// owner flow needs against `/v1/snapshots`:
//
//   * `commitSnapshot(_:)` — POST the owner-signed commitment, parse the
//     server-assigned `SnapshotHandle`.
//   * `uploadBlob(_:ciphertext:)` — PUT the encrypted snapshot blob as
//     `application/octet-stream`. The backend re-hashes the bytes and
//     rejects with `hash_mismatch` if they disagree with the committed
//     `ciphertext_hash`.
//   * `fetchSnapshotBundle(_:)` — GET the bundle (commitment + attestations
//     + key grants) and re-verify every signed inner payload via
//     `ResponseVerification`. The envelope itself is untrusted transport;
//     trust flows through per-payload signatures only.
//   * `fetchBlob(_:)` — stream the ciphertext via `URLSession.bytes(for:)`
//     so the full payload is never buffered in memory (AC #4). Returns
//     `AsyncThrowingStream<Data, Error>` directly — the stream **is** the
//     contract; underlying work runs in an unstructured Task.
//
// Backend `{"error":{"code":...}}` envelopes route through
// `PKENetworkError.from(backendError:)` so error mapping stays in one
// place. Transport faults from `URLSession` collapse to
// `.transport(URLError.Code)`.
//
// Integration tests against `make serve` are deferred to HLAM-47 — no live
// backend exists yet. Unit coverage lives in
// `PKETests/HTTPClient/Endpoints/SnapshotEndpointsTests.swift` and uses the
// same `MockURLProtocol` pattern as `PKEHTTPClientTests.swift`.

#if canImport(Security)
import Foundation
import PKECrypto
import PKEIdentity
import PKEProtocol

// MARK: - Public response types

/// Server-assigned capability handle returned by `POST /v1/snapshots`.
///
/// `blobUploadURL` is optional because the backend may either accept the
/// blob on the canonical `PUT /v1/snapshots/{id}/blob` path or hand back a
/// presigned object-store URL. Callers should prefer the presigned URL
/// when present and fall back to the canonical path otherwise.
public struct SnapshotHandle: Codable, Equatable, Sendable {

    public let snapshotId: String
    public let blobUploadURL: URL?

    public init(snapshotId: String, blobUploadURL: URL?) {
        self.snapshotId = snapshotId
        self.blobUploadURL = blobUploadURL
    }

    enum CodingKeys: String, CodingKey {
        case snapshotId = "snapshot_id"
        case blobUploadURL = "blob_upload_url"
    }
}

/// Snapshot bundle returned by `GET /v1/snapshots/{id}` — the commitment
/// plus every witness attestation and key grant the backend has indexed
/// against that snapshot. `attestations` and `keyGrants` may be empty.
public struct SnapshotBundle: Codable, Equatable, Sendable {

    public let commitment: SnapshotCommitment
    public let attestations: [WitnessAttestation]
    public let keyGrants: [KeyGrant]

    public init(
        commitment: SnapshotCommitment,
        attestations: [WitnessAttestation],
        keyGrants: [KeyGrant]
    ) {
        self.commitment = commitment
        self.attestations = attestations
        self.keyGrants = keyGrants
    }

    enum CodingKeys: String, CodingKey {
        case commitment
        case attestations
        case keyGrants = "key_grants"
    }
}

// MARK: - Endpoint methods

public extension PKEHTTPClient {

    /// POST /v1/snapshots — sign the commitment with the local identity,
    /// send the canonical-JSON body, and parse the returned
    /// `SnapshotHandle`. Errors flow through the standard backend envelope
    /// mapping (`PKENetworkError.from(backendError:)`).
    func commitSnapshot(_ commitment: SnapshotCommitment) async throws -> SnapshotHandle {
        let url = baseURL.appendingPathComponent("v1/snapshots")
        let signedBody: Data
        do {
            signedBody = try RequestSigning.sign(commitment, with: deviceIdentity)
        } catch let cryptoError as CryptoError {
            throw PKENetworkError.encoding(reason: "\(cryptoError)")
        } catch {
            throw PKENetworkError.encoding(reason: "\(error)")
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue(
            RequestSigning.canonicalJSONContentType,
            forHTTPHeaderField: "Content-Type"
        )
        request.httpBody = signedBody

        let (data, response) = try await sendOrTransport(request)
        return try SnapshotEndpointSupport.decodeSuccess(
            data: data,
            response: response,
            acceptedStatuses: [200, 201],
            as: SnapshotHandle.self
        )
    }

    /// PUT /v1/snapshots/{id}/blob — upload the opaque ciphertext as
    /// `application/octet-stream`. The backend re-hashes and rejects with
    /// `hash_mismatch` if the bytes disagree with the committed
    /// `ciphertext_hash`. 204 No Content is the success path.
    func uploadBlob(_ snapshotId: String, ciphertext: Data) async throws {
        let url = baseURL
            .appendingPathComponent("v1/snapshots")
            .appendingPathComponent(snapshotId)
            .appendingPathComponent("blob")

        var request = URLRequest(url: url)
        request.httpMethod = "PUT"
        request.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
        request.httpBody = ciphertext

        let (data, response) = try await sendOrTransport(request)
        let status = response.statusCode
        if status == 200 || status == 204 {
            return
        }
        if let envelope = SnapshotEndpointSupport.decodeErrorEnvelope(data) {
            throw PKENetworkError.from(backendError: envelope)
        }
        throw PKENetworkError.uploadFailed(reason: "HTTP \(status)")
    }

    /// GET /v1/snapshots/{id} — fetch the snapshot bundle and re-verify
    /// every signed inner payload before returning. Verification failure
    /// surfaces as `PKENetworkError.verificationFailed(CryptoError)` —
    /// `ResponseVerification` already raises a typed `PKENetworkError`, so
    /// we simply let it propagate.
    func fetchSnapshotBundle(_ snapshotId: String) async throws -> SnapshotBundle {
        let url = baseURL
            .appendingPathComponent("v1/snapshots")
            .appendingPathComponent(snapshotId)

        var request = URLRequest(url: url)
        request.httpMethod = "GET"

        let (data, response) = try await sendOrTransport(request)
        let bundle = try SnapshotEndpointSupport.decodeSuccess(
            data: data,
            response: response,
            acceptedStatuses: [200],
            as: SnapshotBundle.self
        )

        try ResponseVerification.verify(bundle.commitment)
        try ResponseVerification.verifyAll(
            bundle.attestations.map { $0 as any SignablePayload }
        )
        try ResponseVerification.verifyAll(
            bundle.keyGrants.map { $0 as any SignablePayload }
        )
        return bundle
    }

    /// GET /v1/snapshots/{id}/blob — stream the ciphertext via
    /// `URLSession.bytes(for:)` so the full payload is never buffered.
    /// The returned `AsyncThrowingStream` yields `Data` chunks (one byte
    /// per element from `URLSession.AsyncBytes`; the consumer is free to
    /// accumulate as it sees fit). Transport faults map to
    /// `PKENetworkError.transport(URLError.Code)`; non-200 responses map
    /// to `.uploadFailed(reason: "HTTP \(status)")` — `uploadFailed` is
    /// reused because the taxonomy already covers blob-IO failure shapes.
    ///
    /// The non-async signature is intentional: the stream **is** the
    /// contract. Underlying work runs in an unstructured Task that lives
    /// for the duration of the stream.
    nonisolated func fetchBlob(_ snapshotId: String) -> AsyncThrowingStream<Data, Error> {
        let url = baseURL
            .appendingPathComponent("v1/snapshots")
            .appendingPathComponent(snapshotId)
            .appendingPathComponent("blob")

        return AsyncThrowingStream { continuation in
            let task = Task { [self] in
                await SnapshotEndpointSupport.driveBlobStream(
                    url: url,
                    session: await sessionForStreaming(),
                    continuation: continuation
                )
            }
            continuation.onTermination = { _ in
                task.cancel()
            }
        }
    }

    // MARK: - Shared transport helper

    /// Wraps `send(_:)` so that `URLError`s surface as
    /// `PKENetworkError.transport(_:)` for every endpoint in this file
    /// without duplicating the catch.
    private func sendOrTransport(
        _ request: URLRequest
    ) async throws -> (Data, HTTPURLResponse) {
        do {
            return try await send(request)
        } catch let urlError as URLError {
            throw PKENetworkError.transport(urlError.code)
        }
    }
}

// MARK: - Response parsing

/// File-private helpers for status-code → error mapping and JSON decode
/// wrapping. Kept inside Snapshot.swift per HLAM-151 scope guidance — when
/// a second endpoint module lands these will likely move to a shared file.
internal enum SnapshotEndpointSupport {

    static func decodeSuccess<T: Decodable>(
        data: Data,
        response: HTTPURLResponse,
        acceptedStatuses: Set<Int>,
        as type: T.Type
    ) throws -> T {
        let status = response.statusCode
        if acceptedStatuses.contains(status) {
            do {
                return try JSONDecoder().decode(T.self, from: data)
            } catch {
                throw PKENetworkError.decoding(reason: "\(error)")
            }
        }
        if let envelope = decodeErrorEnvelope(data) {
            throw PKENetworkError.from(backendError: envelope)
        }
        throw PKENetworkError.internalServerError
    }

    static func decodeErrorEnvelope(_ data: Data) -> BackendErrorEnvelope? {
        guard !data.isEmpty else { return nil }
        return try? JSONDecoder().decode(BackendErrorEnvelope.self, from: data)
    }

    /// Drain at most `limit` bytes from `bytes`, returning what was read
    /// (or whatever was available before EOF). Used to inspect a short
    /// error-envelope body on a non-200 streaming response without
    /// buffering the full payload.
    static func collectUpTo(
        bytes: URLSession.AsyncBytes,
        limit: Int
    ) async throws -> Data {
        var collected = Data()
        collected.reserveCapacity(limit)
        for try await byte in bytes {
            collected.append(byte)
            if collected.count >= limit {
                break
            }
        }
        return collected
    }

    /// Drive the underlying `URLSession.bytes(for:)` pipeline for
    /// `fetchBlob`. Lives on `SnapshotEndpointSupport` so the
    /// `AsyncThrowingStream` builder closure in `fetchBlob` stays short.
    static func driveBlobStream(
        url: URL,
        session: URLSession,
        continuation: AsyncThrowingStream<Data, Error>.Continuation
    ) async {
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        do {
            let (bytes, response) = try await session.bytes(for: request)
            guard let httpResponse = response as? HTTPURLResponse else {
                continuation.finish(throwing: PKEHTTPClientError.nonHTTPResponse)
                return
            }
            let status = httpResponse.statusCode
            guard status == 200 else {
                try await finishBlobStreamWithError(
                    bytes: bytes,
                    status: status,
                    continuation: continuation
                )
                return
            }
            for try await byte in bytes {
                continuation.yield(Data([byte]))
            }
            continuation.finish()
        } catch let urlError as URLError {
            continuation.finish(throwing: PKENetworkError.transport(urlError.code))
        } catch let networkError as PKENetworkError {
            continuation.finish(throwing: networkError)
        } catch {
            continuation.finish(throwing: error)
        }
    }

    /// Map a non-200 streaming response to the appropriate
    /// `PKENetworkError`: prefer the backend envelope when the body
    /// decodes, otherwise fall back to `.uploadFailed`.
    private static func finishBlobStreamWithError(
        bytes: URLSession.AsyncBytes,
        status: Int,
        continuation: AsyncThrowingStream<Data, Error>.Continuation
    ) async throws {
        let buffered = try await collectUpTo(bytes: bytes, limit: 4096)
        if let envelope = decodeErrorEnvelope(buffered) {
            continuation.finish(throwing: PKENetworkError.from(backendError: envelope))
        } else {
            continuation.finish(
                throwing: PKENetworkError.uploadFailed(reason: "HTTP \(status)")
            )
        }
    }
}
#endif
