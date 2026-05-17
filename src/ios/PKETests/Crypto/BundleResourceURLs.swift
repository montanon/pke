// Cross-platform shim around `Bundle.urls(forResourcesWithExtension:subdirectory:)`.
//
// Darwin Foundation returns `[URL]?`; swift-corelibs-foundation on Linux
// returns `[NSURL]?`. Direct `urls.append(contentsOf:)` against an
// `[URL]` accumulator therefore fails to compile on Linux with a
// `Element == NSURL` mismatch. Routing every test-target call through
// this helper normalises to `[URL]` on both platforms so the
// `*_vectors_from_bundle` runners share one source.
//
// The implementation casts each entry as `NSURL` and rebuilds a URL from
// its file path:
//   - Darwin: URL bridges to NSURL via Foundation; the cast is the
//     standard auto-bridge and `.path` is non-optional.
//   - Linux: the underlying element already is NSURL; the cast is a
//     no-op and `.path` is optional but populated for valid resources.

import Foundation

enum BundleResourceURLs {

    static func jsonResources(in bundle: Bundle, subdirectory: String?) -> [URL] {
        guard let raw = bundle.urls(
            forResourcesWithExtension: "json",
            subdirectory: subdirectory
        ) else {
            return []
        }
        var result: [URL] = []
        result.reserveCapacity(raw.count)
        for entry in raw {
            guard let path = (entry as NSURL).path else { continue }
            result.append(URL(fileURLWithPath: path))
        }
        return result
    }
}
