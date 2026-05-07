# Session intent runbook

For operators running an MPP session-intent server. Covers startup
recovery behaviour, the failure modes you'll see in logs, and when to flip
the unsettled-revenue escape hatch.

## Crash recovery overview

`SessionBuilder::recover` is a hard prerequisite: `SessionMethod` is not
constructible by any other path, so a server cannot answer `open`,
`verify_voucher`, `topup`, or `close` until recovery has finished walking
every persisted channel.

Recovery runs in two phases.

Phase 1 (inspect) lists every record in `Open`, `CloseAttempting`,
`Closing`, `ClosedPending`, or `ClosedFinalized` and re-checks each one
against the cluster in parallel. The store is read-only during this pass.
Each record produces one of:

- `Resume` for a healthy `Open` channel that matches on-chain state.
- `DropOrphan` for an `Open` record whose PDA never landed (cluster
  returns AccountNotFound).
- `Rollback` for a `CloseAttempting` record whose close broadcast never
  reached the cluster (chain still shows `Open`).
- `RetryClose` for a `CloseAttempting` or `Closing` record where the close
  broadcast confirmed but the post-confirm store updates lagged.
- `TransitionToClosing` for an `Open` record that finds the cluster in
  `Closing` (the payer ran `request_close` directly).
- `Finalize` for a `ClosedPending` record whose PDA is now tombstoned or
  absent.
- `HardFail(...)` for the failure shapes covered in the next section.
- `NoOp` for `ClosedFinalized` records and other terminal-or-synced
  states.

Phase 2 (apply) only runs if the inspect pass produced no hard failures
(or only unsettled-revenue ones with the escape hatch on). It walks each
outcome sequentially and either mutates the store or, for `RetryClose`,
re-runs the close broadcast.

The two-phase split keeps recovery auditable: a crash partway through
phase 2 cannot leave the store half-mutated against an inspect report
the operator never saw, because the inspect report either completed or
already failed loudly.

Atomicity, where you have it:

- Hard-fail gate rejection is atomic. If inspect produced any hard
  failure that survives the `allow_unsettled_on_startup` policy, no
  records are mutated and the server refuses to start.
- Mid-apply failures are not atomic. Phase 2 walks outcomes
  sequentially. If a store outage hits halfway through (a
  `mark_closed_finalized` fails after several earlier records have
  already had `delete` / `mark_close_rollback` / `mark_closed_pending`
  applied), the partial mutations stay. The batch error names the
  channel that failed, not the ones that landed.

If recovery fails mid-apply, fix the underlying issue (store
reachability, RPC reachability, whatever the error names) and restart.
Recovery is idempotent against partial state: the next inspect pass
classifies each record from its current store status, and outcomes
that already ran the previous attempt produce `Resume` / `NoOp` /
`Finalize` instead of repeating.

## When recovery fails: HardFail kinds and what they mean

Hard failures come back as `SessionError::RecoveryBatchFailed { failures }`
with a `Vec<RecoveryFailure>` that enumerates every problem in the batch.
Each `RecoveryFailure` carries a `channel_id` and a typed
`RecoveryFailureKind`:

- `UnsettledRevenue { unsettled }`: the store believes vouchers were
  accepted past the on-chain `settled` watermark, but the channel is
  tombstoned or finalized. The delta in `unsettled` is revenue the server
  recorded but never settled. Inspect the recorded `last_voucher` and
  on-chain `Channel.settled` from the close tx history before deciding
  what to do.
- `RpcFailure(RpcError)`: the inspect pass could not reach the cluster
  for this channel. The wrapped `RpcError` carries the underlying
  transport failure. Usually transient; restart the server once the
  cluster is reachable and recovery will retry.
- `StateInversion { stored, on_chain }`: the store's view of the
  channel and the chain's view contradict each other in a shape recovery
  cannot reconcile (for example, `Closing` in store with the PDA absent
  on-chain, or `CloseAttempting` against an absent PDA). Identifier
  fields (account keys, program IDs) are redacted from the rendered
  message to keep it safe to log; full detail is in the structured
  `RecoveryFailureKind`. Usual causes: the store was edited out of band,
  or two server instances shared a store without coordinating.
  Investigate before continuing. A store-`Closing` against on-chain
  `Open` is the one shape that does NOT surface here: it is treated as
  a soft rollback (probable fork-rollback of `request_close`) and
  downgrades the store back to `Open`.
- `VerifyOpenMismatch { field }`: an `Open` record's `verify_open` failed
  on a specific field (`deposit`, `payer`, `mint`, `distributionHash`,
  etc.). Identifier mismatches surface as the field name only; the
  expected and observed values are not embedded in the variant. Most
  often this fires when the program ID in the record points at a
  different program than the one the chain has the channel under, or
  when splits in the store drifted from the splits the channel was
  opened with.
- `MissingCloseEvidence`: a `ClosedPending` record with no recorded
  `close_tx` signature. Without that evidence,
  `verify_finalized_or_absent` cannot tell a finalized channel apart
  from one that never existed, so recovery refuses to promote the
  record to `ClosedFinalized`. The all-zeros placeholder signature
  documented under "Partially-broadcast close" below sidesteps this:
  any recorded signature, even the placeholder, lets the verify call
  proceed. This variant fires only when the record's `close_tx` field
  is structurally absent.
- `VerifyOpenInternal { message }`: `verify_open` returned a non-RPC
  failure during inspection (decode error, wrong account length, wrong
  discriminator, unexpected encoding). Distinct from `RpcFailure` so
  operators can tell a transport outage apart from a structural
  mismatch in the PDA data.

Recovery hard-fails by default. Startup logs include one
`tracing::error!` per failure plus the RecoveryBatchFailed surface.
Resolve each one before bringing the server up.

## The `--allow-unsettled-on-startup` flag

`RecoveryOptions { allow_unsettled_on_startup: true, .. }` downgrades
`UnsettledRevenue` from a hard failure to a `tracing::warn!` event under
the target `mpp_session_unsettled_revenue_lamports`. The batch then
proceeds and the server starts.

This is the post-disaster-recovery escape hatch. Use it only when:

1. The unsettled revenue has been investigated by hand: read the
   on-chain close tx, read the recorded `last_voucher`, decide whether
   the difference is recoverable through manual settlement or has to be
   written off.
2. The decision is documented somewhere durable (audit log, ticket).
3. You want the server to come up despite the open question, because
   blocking startup costs more than serving with the warning attached.

The flag is operator-supplied through whatever surface wires
`RecoveryOptions` (env var, CLI arg, config file). It does not
downgrade any other failure kind: an `RpcFailure`, `StateInversion`,
`VerifyOpenMismatch`, `VerifyOpenInternal`, or `MissingCloseEvidence`
mixed into the same batch still surfaces as `RecoveryBatchFailed`.
Restart with `allow_unsettled_on_startup = false` once the unsettled
question is closed.

Keep `mpp_session_unsettled_revenue_lamports` on a dashboard or grep
target so the warning doesn't fade into background noise.

## Common operational scenarios

### Restart with healthy channels (the common case)

The store has some `Open` records, the cluster confirms each one, every
record produces `Resume`, and phase 2 is a sequence of no-ops. The server
comes up and starts serving. Successful recovery emits one
`tracing::info!` per mutation, but `Resume` outcomes are silent, so a
clean recovery is mostly empty in the logs.

### Partially-broadcast close after a crash

The server crashed between submitting the distribute tx and recording the
post-confirm store updates. Inspection finds a `CloseAttempting` record
against an on-chain `Closing` or tombstoned PDA. The outcome is
`RetryClose`, and phase 2 walks the close orchestration's broadcast and
post-confirm phases (using a freshly-fetched blockhash) to bring the
record forward to `ClosedPending` and best-effort `ClosedFinalized`.

If the chain is already tombstoned, `RetryClose` skips the broadcast and
just pushes the store from `CloseAttempting` (or `Closing`) to
`ClosedPending` using the previously-recorded `record.close_tx` (or a
zeroed signature if none was captured). The operator should inspect the
on-chain history if they need the canonical close signature.

When the original close tx signature was not persisted (rare, indicates
a crash mid-orchestration between broadcast and `record_close_signature`),
the store records the all-zeros signature `1111...1111` as a placeholder.
Operators can grep for that signature to surface these channels.

### Orphaned `Open` from an open tx that never confirmed

The open handler returned `OpenTxUnconfirmed` and the operator never
re-ran reconciliation. Inspection finds an `Open` record against an
absent PDA. The outcome is `DropOrphan`, and phase 2 deletes the record
so the channel id is free again. The client can re-issue a fresh open
challenge and start over.

## Known limitations (v1)

Deferred to v2 and not handled by the v1 recovery layer. Wire
monitoring and operator playbooks around these.

- No exponential backoff or max-retry counter. If the RPC layer is
  flapping or the cluster is slow, repeated startup attempts will keep
  re-entering recovery without spacing the load. Pathological RPC
  failures can produce a restart-loop retry storm. Watch for repeated
  recovery failures in the startup logs and intervene (cool the host,
  pause restarts, route to a different RPC) rather than relying on the
  recovery layer to back off on its own.
- No 429/503 throttle handling. The parallel inspect pass defaults to
  `parallelism: 8`, configurable via `RecoveryOptions::parallelism`, and
  does not detect or back off on RPC throttle responses. Operators with
  constrained RPC quotas should reduce `parallelism` to keep the inspect
  burst inside the quota.
