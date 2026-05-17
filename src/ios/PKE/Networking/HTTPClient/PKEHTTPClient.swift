// HLAM-146 — `PKEHTTPClient` skeleton.
//
// Apple-only foundation actor for every backend REST call the iOS app makes
// (HLAM-49). Holds a base URL, an injected `DeviceIdentity` (HLAM-8), and a
// URLSession configured with `URLSessionConfiguration.default` so App
// Transport Security applies unmodified — there is no `NSAllowsArbitraryLoads`
// override anywhere in the client.
//
// Actor isolation is the only synchronization point: concurrent callers from
// SwiftUI, the witness transports, and any background task can issue requests
// without external locking. `URLSession.data(for:)` is itself thread-safe and
// returns when the response is fully buffered.
//
// Later stories under HLAM-49 (#147–#155) layer canonical-JSON encoding,
// request signing, response verification, endpoint methods, and the
// `PKENetworkError` taxonomy on top of this primitive. This file is
// intentionally narrow — it owns transport plumbing only.

#if canImport(Security)
import Foundation
import PKEIdentity

public actor PKEHTTPClient {
    public let baseURL: URL
    private let identity: DeviceIdentity
    private let session: URLSession

    /// Production initializer. Uses `URLSessionConfiguration.default` so ATS
    /// is enforced and no arbitrary-load exemptions are configured.
    public init(baseURL: URL, identity: DeviceIdentity) {
        self.init(
            baseURL: baseURL,
            identity: identity,
            configuration: .default
        )
    }

    /// Internal initializer used by tests to inject a configuration carrying
    /// a `URLProtocol` mock. Production code should call the two-argument
    /// initializer above.
    internal init(
        baseURL: URL,
        identity: DeviceIdentity,
        configuration: URLSessionConfiguration
    ) {
        self.baseURL = baseURL
        self.identity = identity
        self.session = URLSession(configuration: configuration)
    }

    /// Issues `request` over the underlying session and returns the response
    /// body alongside the typed `HTTPURLResponse`. Non-HTTP responses (which
    /// `URLSession` should never return for an `http(s)` URL but we cannot
    /// statically rule out) surface as `PKEHTTPClientError.nonHTTPResponse`.
    ///
    /// This is the transport primitive that later HLAM-49 stories build on.
    /// It performs no signing, no canonicalization, and no verification.
    public func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let (data, response) = try await session.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw PKEHTTPClientError.nonHTTPResponse
        }
        return (data, httpResponse)
    }
}

/// Errors raised by the transport primitive itself. The richer
/// `PKENetworkError` taxonomy (HLAM-154) wraps these along with the
/// signing/verification/encoding cases once those layers exist.
public enum PKEHTTPClientError: Error, Equatable, Sendable {
    case nonHTTPResponse
}
#endif
