// swift-tools-version: 5.9
//
// PKE — iOS Swift Package
//
// Declares three library targets and matching test targets:
//
//   PKECrypto    — primitives wrapping swift-crypto / CryptoKit
//   PKEProtocol  — wire-level snapshot / attestation / ledger types
//   PKEIdentity  — Keychain-backed identity (Apple platforms only)
//
// Cross-platform notes:
//
//   - PKEIdentity sources are wrapped in `#if canImport(Security)` so the
//     module compiles to an empty translation unit on Linux. The library is
//     still declared on every platform so dependents resolve.
//
//   - PKECryptoTests carries the shared test-vector corpus as a processed
//     resource via a symlink at `PKETests/Crypto/Resources/test_vectors`
//     pointing at `../../../../shared/test_vectors`. The symlink must
//     resolve to an existing directory; if `src/shared/test_vectors/` is
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
        .library(name: "PKEIdentity", targets: ["PKEIdentity"])
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
        .testTarget(
            name: "PKECryptoTests",
            dependencies: ["PKECrypto"],
            path: "PKETests/Crypto",
            resources: [
                .process("Resources")
            ]
        ),
        .testTarget(
            name: "PKEProtocolTests",
            dependencies: ["PKEProtocol"],
            path: "PKETests/Protocol"
        ),
        .testTarget(
            name: "PKEIdentityTests",
            dependencies: ["PKEIdentity"],
            path: "PKETests/Identity"
        )
    ]
)
