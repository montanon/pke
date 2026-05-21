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
//   PKEApp         — SwiftUI navigation skeleton + Settings/Limitations screens
//
// Cross-platform notes:
//
//   - PKEIdentity, PKEHTTPClient, and PKESession sources are wrapped in
//     `#if canImport(Security)` so the modules compile to empty translation
//     units on Linux. The libraries are still declared on every platform so
//     dependents resolve.
//
//   - PKEApp gates the `@main App` type with `#if canImport(UIKit) &&
//     canImport(SwiftUI)`, the views with `#if canImport(SwiftUI)`, and
//     `UIKitPasteboardWriter` with `#if canImport(UIKit)`. On Linux the
//     library compiles as an effectively empty translation unit while the
//     pure-data types (Role, AppRoute, Limitations, Fingerprint,
//     BundleInfo, SettingsViewModel, PasteboardWriting, NoopPasteboardWriter)
//     and the navigation-state machine remain testable on macOS.
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
        .iOS(.v17),
        .macOS(.v13)
    ],
    products: [
        .library(name: "PKECrypto", targets: ["PKECrypto"]),
        .library(name: "PKEProtocol", targets: ["PKEProtocol"]),
        .library(name: "PKEIdentity", targets: ["PKEIdentity"]),
        .library(name: "PKEWitness", targets: ["PKEWitness"]),
        .library(name: "PKEHTTPClient", targets: ["PKEHTTPClient"]),
        .library(name: "PKESession", targets: ["PKESession"]),
        .library(name: "PKERecipient", targets: ["PKERecipient"]),
        .library(name: "PKEApp", targets: ["PKEApp"])
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
        // PKERecipient — recipient-flow decryption service (HLAM-118).
        //
        // Cross-platform module. Composes `KeyWrap.unwrap` + `AEAD.open`
        // behind a typed `DecryptionError` surface. The unwrap step is
        // injected via a closure so Apple platforms can wire
        // `DeviceIdentitySession.unwrap` (Security-framework gated) and
        // Linux CI can wire `KeyWrap.unwrap` directly.
        .target(
            name: "PKERecipient",
            dependencies: [
                "PKECrypto",
                "PKEProtocol",
                .product(name: "Crypto", package: "swift-crypto")
            ],
            path: "PKE/Services/Recipient"
        ),
        // PKEApp — SwiftUI navigation skeleton (HLAM-92) + Settings/Limitations
        // screens (HLAM-95).
        //
        // Hosts the AppRoute enum, AppNavigationState ObservableObject,
        // role-selection view, placeholder role screens, plus the Settings
        // and Limitations screens (`SettingsView`, `LimitationsView`) and
        // their support layer (`Fingerprint`, `Limitations`, `BundleInfo`,
        // `PasteboardWriting`, `SettingsViewModel`). Sources span two
        // sibling directories under PKE/ — `App/` for state & routing,
        // `Views/` for SwiftUI views and helpers — declared via the
        // `sources:` array so the target picks up both without
        // overlapping the sibling library targets above. The `@main App`
        // type in PKEApp.swift is gated `#if canImport(UIKit)` so the
        // library still compiles on Linux CI as an empty TU.
        .target(
            name: "PKEApp",
            dependencies: ["PKECrypto"],
            path: "PKE",
            sources: ["App", "Views"]
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
            dependencies: [
                "PKEWitness",
                "PKECrypto",
                .product(name: "Crypto", package: "swift-crypto")
            ],
            path: "PKETests/Witness",
            exclude: [
                "MPC/two_device_test_plan.md"
            ]
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
        ),
        // PKERecipientTests reuses the shared crypto vector corpus via a
        // symlink under Resources/test_vectors — same pattern as
        // PKECryptoTests. The `.process` resource declaration enforces
        // basename uniqueness so the test_vectors/README.md is excluded.
        .testTarget(
            name: "PKERecipientTests",
            dependencies: [
                "PKERecipient",
                "PKECrypto",
                "PKEProtocol",
                .product(name: "Crypto", package: "swift-crypto")
            ],
            path: "PKETests/Recipient",
            exclude: [
                "Resources/test_vectors/README.md"
            ],
            resources: [
                .process("Resources/test_vectors")
            ]
        ),
        .testTarget(
            name: "PKEAppTests",
            dependencies: ["PKEApp"],
            path: "PKETests/App"
        )
    ]
)
