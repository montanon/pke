# Witness Session State Machine (HLAM-110)

`WitnessSessionMachine` is the witness-side coordinator that drives a single
`WitnessTransport`'s `runWitness(sign:)` pipeline through a typed,
observable state graph. It sits between transport plumbing
(`WitnessTransport`, `WitnessListener`, `SessionNonceTracker`) and the UI
that renders "incoming request → user review → approve / decline".

## State graph

```
                       ┌─────────────────┐
                       │     .idle       │◀────────goToBackground()────┐
                       └─────────────────┘                             │
                              │ startListening()                       │
                              ▼                                        │
                       ┌─────────────────┐                             │
            ┌─────────▶│   .available    │──────goToBackground()───────┤
            │          └─────────────────┘                             │
            │                 │ transport delivers inbound request     │
            │                 ▼                                        │
            │          ┌─────────────────┐                             │
            │          │.receivingCommitment                           │
            │          └─────────────────┘                             │
            │                 ▼                                        │
            │          ┌─────────────────┐                             │
            │          │   .verifying    │──verifier throws──┐         │
            │          └─────────────────┘                   │         │
            │                 │ verifier ok                  │         │
            │                 ▼                              ▼         │
            │          ┌─────────────────┐         ┌──────────────────┐│
            │          │  duplicate?     │──yes───▶│  .failed(.dup..  ││
            │          └─────────────────┘         └──────────────────┘│
            │                 │ no                            │       │
            │                 ▼                               │       │
            │          ┌─────────────────┐                    │       │
            │          │  .userReview    │──timeout──┐        │       │
            │          └─────────────────┘           │        │       │
            │            │            │              ▼        │       │
            │       approve         decline   ┌──────────────────┐    │
            │            │            │       │  .failed(.tmo..) │    │
            │            ▼            ▼       └──────────────────┘    │
            │     ┌──────────┐ ┌──────────┐         │                 │
            │     │ .signing │ │.declined │         │                 │
            │     └──────────┘ └──────────┘         │                 │
            │            │            │              │                │
            │      signer throws      │              │                │
            │            │            │              │                │
            │            ▼            │              │                │
            │     ┌──────────────────┐│              │                │
            │     │.failed(.sigInvld)│              │                 │
            │     └──────────────────┘              │                 │
            │            │            │              │                │
            │       signer ok         │              │                │
            │            ▼            │              │                │
            │     ┌──────────┐         │             │                │
            │     │.returned │         │             │                │
            │     └──────────┘         │             │                │
            │            │            │              │                │
            └────────────┴────────────┴──────────────┘                │
                  (resetToAvailableIfListening)                       │
                                                                      │
                                                                      │
                       (any state) ─── goToBackground() ──────────────┘
```

## Transition table

| From | Trigger | To | Side effects | Sign-closure exit |
|---|---|---|---|---|
| `.idle` | `startListening()` | `.available` | spawns child `Task` that calls `transport.runWitness(sign:)` | — |
| `.available` | sign closure invoked with `WitnessSession` | `.receivingCommitment` → `.verifying` | enters in-flight gate; serialises with any prior in-flight request | — |
| `.verifying` | `verifier` throws | `.failed(.verifierThrew(reason:))` → `.available` | nonce cache *unchanged*; resets to available | `throws Failure.verifierThrew` |
| `.verifying` | `requestNonce` in nonce cache | `.failed(.duplicateNonce)` → `.available` | no cache mutation; resets | `throws Failure.duplicateNonce` |
| `.verifying` | nonce fresh + verifier ok | `.userReview(incoming)` | inserts `requestNonce` into bounded FIFO cache | suspends on review continuation |
| `.userReview` | `approve()` | `.signing` | cancels review-timeout task | — |
| `.userReview` | `decline()` | `.declined` → `.available` | cancels review-timeout task; resets | `throws Failure.declined` |
| `.userReview` | review-timeout fires (default 30s) | `.failed(.reviewTimeout)` → `.available` | resets | `throws Failure.reviewTimeout` |
| `.signing` | `signer` returns ok | `.returned` → `.available` | resets | returns `WitnessAttestation` |
| `.signing` | `signer` throws | `.failed(.signatureInvalid)` → `.available` | resets | `throws Failure.signatureInvalid` |
| any (non-`.idle`) | `goToBackground()` | `.idle` | cancels listener task; cancels timeout; resumes any pending review as `.decline`; drains in-flight waiters; calls `transport.stop()` | mid-flight body sees `.idle`, throws `Failure.declined` |

## Replay-cache contract

* `RecentNonceCache` — bounded FIFO of `Data` (the `requestNonce`).
* Default capacity: 64. Override via `WitnessSessionMachine(cacheCapacity:)`.
* Eviction: oldest insertion (`order.removeFirst()`) when at capacity *and*
  a *new* nonce arrives. A duplicate insert returns `false` and does NOT
  re-evict — duplicates never disturb the FIFO.
* Lifetime: in-memory only, scoped to one `WitnessSessionMachine` instance.
  Cleared on app restart. Cross-restart replay protection is deferred —
  the 30-second witness window (HLAM-50 / `WitnessDispatcher`) mitigates
  force-quit-then-rejoin in the meantime (see
  `context/08_security_assumptions.md`).
* Scope distinction:
  * `RecentNonceCache` — replay detection *within* one witness machine
    instance, keyed by `requestNonce`.
  * `SessionNonceTracker` — single-sign rule *across* listener invocations,
    keyed by `(sessionNonce, witnessKey)`. Composed by the listener layer,
    not by the state machine.

## `WitnessTransport` integration

The machine drives the existing `runWitness(sign:)` seam — it does not
extend the transport protocol. The injected sign closure routes inbound
requests through the actor-isolated `process(session:)` body:

```swift
listenerTask = Task {
    try? await transport.runWitness(sign: closure)
}
```

The closure produces a `WitnessAttestation` on approval or throws on
decline / replay / timeout / failure. The transport's contract owns the
"how to surface the error" semantics — `WitnessListener` already absorbs
sign-closure errors so they don't crash other transports.

This addresses the AC's `acceptIncoming()` / `respond(.decline)` shape:

* "transport is subscribed" → `runWitness(sign:)` is called from
  `startListening()`; tested by spy-transport invocation count.
* "decline response is sent" → sign closure throws `Failure.declined`,
  which the transport propagates per its own contract.

## Concurrency model

`WitnessSessionMachine` is an `actor` — all mutable state lives behind
isolation. Multiple inbound requests are serialised via an internal
in-flight gate (`inFlight + waiters`): the second `process` call awaits
the first to finish before running its own state-machine body. This
satisfies the "Each handled in order" edge-case row without an explicit
queue.

`AsyncStream<State>` observer fan-out runs inside the actor (synchronous
yield from the actor's executor). Observers see every transition in
order; cancelling a subscription releases its slot via the stream's
`onTermination` hook, which `Task`s back into the actor to remove the
record.

## Edge cases

| Scenario | Behaviour |
|---|---|
| Concurrent inbound requests | Serialised by `inFlight` gate; second request waits for first to leave `.userReview` (approve / decline / timeout) before its `.receivingCommitment` transition fires. Cache prevents same-nonce replay across the two. |
| User leaves a `.userReview` without deciding | `reviewTimeoutTask` fires after `reviewTimeout` (default 30s) → `.failed(.reviewTimeout)` → `.available`. Sign closure throws `Failure.reviewTimeout`. |
| Transport-level signature failure on inbound | The injected `verifier` throws → `.failed(.verifierThrew(reason:))` → `.available`. No peer drop in MVP — per F8 Story #5, blocklist requires 3 consecutive failures (deferred). |
| `goToBackground()` while in `.userReview` | `.idle` transition fires first; review continuation resumes as `.decline`; the post-await branch of `process` sees `state == .idle` and throws `Failure.declined` without overwriting `.idle`. Listener task is cancelled; `transport.stop()` is awaited. |
| `goToBackground()` from `.idle` | No-op. |
| `startListening()` while already `.available` | No-op (state guard). The transport's existing `runWitness` task remains the sole consumer. |
| `approve()` / `decline()` with no pending review | No-op (continuation guard). |

## Cross-references

* HLAM-46 — iOS Witness Flow (parent feature)
* HLAM-50 — `WitnessTransport` seam, `WitnessDispatcher`, `WitnessListener`,
  `SessionNonceTracker`, `AttestationStrength`
* HLAM-129 — `WitnessListener` implementation
* HLAM-130 — `SessionNonceTracker` implementation
* HLAM-36 — full `PKEProtocol` Codable envelope (will replace
  `WitnessTypes.swift` placeholders and introduce a real `requestNonce`
  field distinct from `sessionNonce`)
