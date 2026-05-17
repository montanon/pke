// Intentionally minimal.
//
// The PKE iOS app's `@main public struct PKEApp: App` lives in the
// `PKEApp` SwiftPM library (HLAM-92). The Xcode `PKE` app target links
// that library so HLAM-92's `@main` becomes the executable entry point;
// this file exists only to satisfy the Swift driver's need for at least
// one input source in the app target's compile graph.
//
// Located under `PKEAppHost/` rather than `PKE/App/` so the SwiftPM
// `PKEApp` library (which sweeps `PKE/App` and `PKE/Views`) does not
// also compile it.

enum PKEAppHost {}
