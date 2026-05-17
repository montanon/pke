// swift-tools-version: 5.9
//
// PKE — iOS Swift Package
//
// Declares library targets and matching test targets:
//
//   PKECrypto      — primitives wrapping swift-crypto / CryptoKit
//   PKEProtocol    — wire-level snapshot / attestation / ledger types
//   PKEIdentity    — Keychain-backed identity (Apple platforms only)
//   PKEWitness     — transport-agnostic witness flow
//   PKEHTTPClient  — backend REST transport (Apple platforms only)
//   PKESession     — @MainActor identity-session wrapper (Apple platforms only)
//
// Cross-platform notes:
//
//   - PKEIdentity, PKEHTTPClient, and PKESession sources are wrapped in
//     `#if canImport(Security)` so the modules compile to empty translation
//     units on Linux. The libraries are still declared on every platform so
//     dependents resolve.
//
//   - PKECryptoTests and PKEProtocolTests carry the shared test-vector
//     corpus via symlinks under their `Resources/` directory, surfaced as
//     `.process` resources so SwiftPM resolves the symlink targets into
//     the test bundle. `Resources/test_vectors/README.md` is excluded
//     because `.process` enforces basename uniqueness and we don't need
//     the docs file in the bundle. PKEProtocolTests reuses the
//     `context/examples/` directory (containing both `.example.json`
//     fixtures and their `.canonical-bytes` parity targets). The symlinks
//     must resolve to existing directories; if a target directory is
//     missing, SwiftPM will fail resource processing with a clear
//     "resource not found" error. Note: `.process` flattens every JSON to
//     the bundle root and `.copy` preserves the symlink verbatim (with a
//     relative target that no longer resolves from inside the bundle), so
//     `Bundle.module`-based subdirectory lookups don't work. New vector
//     runners should resolve fixture paths via `#filePath` instead.
//

import PackageDescription

let package = Package(
    name: "PKE",
    platforms: [
        .iOS(.v16),
        .macOS(.v13)
    ],
    products: [
        .library(name: "PKECrypto", targets: ["PKECrypto"]),
        .library(name: "PKEProtocol", targets: ["PKEProtocol"]),
        .library(name: "PKEIdentity", targets: ["PKEIdentity"]),
        .library(name: "PKEWitness", targets: ["PKEWitness"]),
        .library(name: "PKEHTTPClient", targets: ["PKEHTTPClient"]),
        .library(name: "PKESession", targets: ["PKESession"])
    ],
    dependencies: [
        .package(
            url: "https://github.com/apple/swift-crypto.git",
            .upToNextMajor(from: "3.0.0")
        )
    ],
    targets: [
        .target(
            name: "PKECrypto",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto")
            ],
            path: "PKE/Services/Crypto"
        ),
        .target(
            name: "PKEProtocol",
            dependencies: ["PKECrypto"],
            path: "PKE/Models/Protocol"
        ),
        .target(
            name: "PKEIdentity",
            dependencies: ["PKECrypto"],
            path: "PKE/Services/Identity"
        ),
        .target(
            name: "PKEWitness",
            path: "PKE/Networking/Witness"
        ),
        .target(
            name: "PKEHTTPClient",
            dependencies: ["PKEIdentity", "PKECrypto", "PKEProtocol"],
            path: "PKE/Networking/HTTPClient"
        ),
        .target(
            name: "PKESession",
            dependencies: [
                "PKEIdentity",
                "PKEProtocol",
                "PKECrypto",
                .product(name: "Crypto", package: "swift-crypto")
            ],
            path: "PKE/Services/Session"
        ),
        .testTarget(
            name: "PKECryptoTests",
            dependencies: ["PKECrypto"],
            path: "PKETests/Crypto",
            exclude: [
                "Resources/test_vectors/README.md"
            ],
            resources: [
                .process("Resources/test_vectors")
            ]
        ),
        .testTarget(
            name: "PKEProtocolTests",
            dependencies: ["PKEProtocol"],
            path: "PKETests/Protocol",
            resources: [
                .process("Resources/examples")
            ]
        ),
        .testTarget(
            name: "PKEIdentityTests",
            dependencies: [
                "PKEIdentity",
                "PKECrypto",
                .product(name: "Crypto", package: "swift-crypto")
            ],
            path: "PKETests/Identity"
        ),
        .testTarget(
            name: "PKEWitnessTests",
            dependencies: ["PKEWitness"],
            path: "PKETests/Witness"
        ),
        .testTarget(
            name: "PKEHTTPClientTests",
            dependencies: [
                "PKEHTTPClient",
                "PKEIdentity",
                "PKECrypto",
                "PKEProtocol",
                .product(name: "Crypto", package: "swift-crypto")
            ],
            path: "PKETests/HTTPClient"
        ),
        .testTarget(
            name: "PKESessionTests",
            dependencies: [
                "PKESession",
                "PKEIdentity",
                "PKEProtocol",
                "PKECrypto",
                .product(name: "Crypto", package: "swift-crypto")
            ],
            path: "PKETests/Session"
        )
    ]
)
