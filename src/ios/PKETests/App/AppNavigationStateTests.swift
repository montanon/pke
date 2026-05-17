// Coverage for `AppNavigationState` — every acceptance criterion of
// HLAM-92 plus the documented edge cases. `AppNavigationState` is
// `@MainActor`-isolated so every test runs on the main actor.
//
// Gated `#if canImport(Combine)` because the type under test depends on
// Combine, which is Apple-only.

#if canImport(Combine)
import Combine
import XCTest
@testable import PKEApp

@MainActor
final class AppNavigationStateTests: XCTestCase {

    // MARK: AC#1 — fresh install

    func testFreshInstallRoleIsNilAndPathIsEmpty() {
        let state = AppNavigationState(defaults: IsolatedDefaults.make())

        XCTAssertNil(state.role)
        XCTAssertTrue(state.path.isEmpty)
        XCTAssertNil(state.currentSnapshotID)
        XCTAssertNil(state.cancellationNotice)
    }

    // MARK: AC#2 — select Owner

    func testSelectOwnerSetsRoleAndPushesOwnerHome() {
        let state = AppNavigationState(defaults: IsolatedDefaults.make())

        state.select(role: .owner)

        XCTAssertEqual(state.role, .owner)
        XCTAssertEqual(state.path, [.ownerHome])
    }

    func testSelectOwnerPersistsRawValueToUserDefaults() {
        let defaults = IsolatedDefaults.make()
        let state = AppNavigationState(defaults: defaults)

        state.select(role: .owner)

        XCTAssertEqual(defaults.string(forKey: AppNavigationState.lastRoleKey), "owner")
    }

    // MARK: AC#3 — switch role discards previous path

    func testSelectWitnessAfterOwnerReplacesRoleAndPath() {
        let state = AppNavigationState(defaults: IsolatedDefaults.make())
        state.select(role: .owner)

        state.select(role: .witness)

        XCTAssertEqual(state.role, .witness)
        XCTAssertEqual(state.path, [.witnessAvailable])
    }

    func testSelectRecipientAfterWitnessReplacesRoleAndPath() {
        let state = AppNavigationState(defaults: IsolatedDefaults.make())
        state.select(role: .witness)

        state.select(role: .recipient)

        XCTAssertEqual(state.role, .recipient)
        XCTAssertEqual(state.path, [.recipientGrants])
    }

    // MARK: AC#4 — currentSnapshotID slot

    func testCurrentSnapshotIDDefaultsToNil() {
        let state = AppNavigationState(defaults: IsolatedDefaults.make())

        XCTAssertNil(state.currentSnapshotID)
    }

    func testCurrentSnapshotIDIsMutable() {
        let state = AppNavigationState(defaults: IsolatedDefaults.make())

        state.currentSnapshotID = "snap-123"

        XCTAssertEqual(state.currentSnapshotID, "snap-123")
    }

    // MARK: AC#5 — persistence + nav-stack reset

    func testInitHydratesRoleAndPathFromUserDefaults() {
        let defaults = IsolatedDefaults.make()
        defaults.set(Role.witness.rawValue, forKey: AppNavigationState.lastRoleKey)

        let state = AppNavigationState(defaults: defaults)

        XCTAssertEqual(state.role, .witness)
        XCTAssertEqual(state.path, [.witnessAvailable])
    }

    func testInitWithUnknownPersistedRoleIsIgnored() {
        let defaults = IsolatedDefaults.make()
        defaults.set("garbage-role", forKey: AppNavigationState.lastRoleKey)

        let state = AppNavigationState(defaults: defaults)

        XCTAssertNil(state.role)
        XCTAssertTrue(state.path.isEmpty)
    }

    func testResetNavigationStackPopsToRoleHomeAndPreservesRole() {
        let state = AppNavigationState(defaults: IsolatedDefaults.make())
        state.select(role: .owner)
        state.path = [.ownerHome, .settings]

        state.resetNavigationStack()

        XCTAssertEqual(state.role, .owner)
        XCTAssertEqual(state.path, [.ownerHome])
    }

    func testResetNavigationStackWithoutRoleClearsPath() {
        let state = AppNavigationState(defaults: IsolatedDefaults.make())
        state.path = [.settings]

        state.resetNavigationStack()

        XCTAssertNil(state.role)
        XCTAssertTrue(state.path.isEmpty)
    }

    func testResetNavigationStackOptionallySetsNotice() {
        let state = AppNavigationState(defaults: IsolatedDefaults.make())
        state.select(role: .owner)

        state.resetNavigationStack(notice: "Background reset")

        XCTAssertEqual(state.cancellationNotice, "Background reset")
        XCTAssertEqual(state.path, [.ownerHome])
    }

    func testResetNavigationStackWithNilNoticePreservesPendingNotice() {
        let state = AppNavigationState(defaults: IsolatedDefaults.make())
        state.select(role: .owner)
        state.currentSnapshotID = "snap-1"
        state.select(role: .recipient)
        XCTAssertNotNil(state.cancellationNotice)

        state.resetNavigationStack(notice: nil)

        XCTAssertNotNil(state.cancellationNotice)
    }

    // MARK: Edge case — role switch mid-flow

    func testRoleSwitchMidFlowSetsCancellationNoticeAndClearsSnapshot() {
        let state = AppNavigationState(defaults: IsolatedDefaults.make())
        state.select(role: .owner)
        state.currentSnapshotID = "snap-abc"

        state.select(role: .recipient)

        XCTAssertEqual(state.role, .recipient)
        XCTAssertNil(state.currentSnapshotID)
        XCTAssertEqual(
            state.cancellationNotice,
            AppNavigationState.defaultCancellationNotice
        )
    }

    func testRoleSwitchWithoutInFlightSnapshotDoesNotSetNotice() {
        let state = AppNavigationState(defaults: IsolatedDefaults.make())
        state.select(role: .owner)
        XCTAssertNil(state.currentSnapshotID)

        state.select(role: .witness)

        XCTAssertNil(state.cancellationNotice)
    }

    func testFirstRoleSelectionDoesNotSetNoticeEvenIfSnapshotIDSomehowSet() {
        // Defensive: first selection (role was nil) must never trigger the
        // banner — there was no previous flow to cancel.
        let state = AppNavigationState(defaults: IsolatedDefaults.make())
        state.currentSnapshotID = "snap-leaked"

        state.select(role: .owner)

        XCTAssertNil(state.cancellationNotice)
        XCTAssertNil(state.currentSnapshotID)
    }

    // MARK: Idempotence

    func testReselectSameRoleIsNoOp() {
        let state = AppNavigationState(defaults: IsolatedDefaults.make())
        state.select(role: .owner)
        state.path = [.ownerHome, .settings]

        state.select(role: .owner)

        XCTAssertEqual(state.role, .owner)
        XCTAssertEqual(state.path, [.ownerHome, .settings])
    }

    // MARK: Cancellation banner

    func testDismissCancellationNoticeClearsBanner() {
        let state = AppNavigationState(defaults: IsolatedDefaults.make())
        state.select(role: .owner)
        state.currentSnapshotID = "snap-1"
        state.select(role: .witness)
        XCTAssertNotNil(state.cancellationNotice)

        state.dismissCancellationNotice()

        XCTAssertNil(state.cancellationNotice)
    }

    // MARK: Observation

    func testSelectPublishesChangeToObservers() {
        let state = AppNavigationState(defaults: IsolatedDefaults.make())
        let expectation = XCTestExpectation(description: "objectWillChange fires on select")
        var cancellables: Set<AnyCancellable> = []
        state.objectWillChange
            .sink { _ in expectation.fulfill() }
            .store(in: &cancellables)

        state.select(role: .owner)

        wait(for: [expectation], timeout: 1.0)
        cancellables.removeAll()
    }
}
#endif
