// Central navigation state for the PKE iOS app.
//
// All published state mutates on the main actor. Persistence is mediated by
// an injected `UserDefaults` so tests can swap in an isolated suite without
// touching the host's `.standard` defaults.
//
// Acceptance criteria mapping (HLAM-92):
//   AC#1 fresh install → `role == nil`, `path == []`
//   AC#2 select(.owner) → role=.owner, path=[.ownerHome], persisted
//   AC#3 select(.witness) after owner → role=.witness, path=[.witnessAvailable]
//   AC#4 currentSnapshotID is nullable, mutable
//   AC#5 backgrounding → path cleared, role survives (via UserDefaults)
//   AC#6 AppRoute enum coverage — see AppRoute.swift
//
// Edge case: if the user switches role mid-flow (currentSnapshotID != nil),
// `cancellationNotice` is set so the placeholder/role screen can surface a
// "cancelled by user" banner. F9/F10/F11 will own the richer state-machine
// cancellation; this slot is the minimum API for that handoff.
//
// Gated `#if canImport(Combine)` because `ObservableObject` and
// `@Published` come from Combine, which is Apple-only. On Linux the type
// is absent and the rest of `PKEApp` (Role, AppRoute) remains compilable
// for cross-platform CI.

#if canImport(Combine)
import Combine
import Foundation

@MainActor
public final class AppNavigationState: ObservableObject {
    public static let lastRoleKey = "pke.lastRole"
    public static let defaultCancellationNotice = "Previous flow cancelled by user."

    @Published public private(set) var role: Role?
    @Published public var path: [AppRoute] = []
    @Published public var currentSnapshotID: String?
    @Published public private(set) var cancellationNotice: String?

    private let defaults: UserDefaults

    public init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        let hydrated = defaults.string(forKey: Self.lastRoleKey).flatMap(Role.init(rawValue:))
        self.role = hydrated
        if let hydrated {
            self.path = [AppRoute.home(for: hydrated)]
        }
    }

    /// Switch to a role. Idempotent — selecting the current role leaves
    /// `path` unchanged. Switching while a flow is in flight
    /// (`currentSnapshotID != nil`) surfaces a cancellation banner and
    /// clears the snapshot ID.
    public func select(role newRole: Role) {
        if role == newRole {
            return
        }
        if role != nil, currentSnapshotID != nil {
            cancellationNotice = Self.defaultCancellationNotice
        }
        currentSnapshotID = nil
        role = newRole
        path = [AppRoute.home(for: newRole)]
        defaults.set(newRole.rawValue, forKey: Self.lastRoleKey)
    }

    /// Reset the navigation stack to the role's home (or empty if no role
    /// has been selected yet) and, optionally, set a banner. The role is
    /// preserved. Called from `PKEApp`'s ScenePhase observer on
    /// background→foreground transitions so half-finished flows do not
    /// leak back into the UI. If a `cancellationNotice` is already
    /// pending, the new `notice` overwrites it — by convention callers
    /// pass `nil` (the default) on background recovery so an
    /// already-pending banner survives.
    public func resetNavigationStack(notice: String? = nil) {
        if let role {
            path = [AppRoute.home(for: role)]
        } else {
            path = []
        }
        if let notice {
            cancellationNotice = notice
        }
    }

    /// Acknowledge and clear the cancellation banner. Called by the role
    /// screen's banner-dismiss button.
    public func dismissCancellationNotice() {
        cancellationNotice = nil
    }
}
#endif
