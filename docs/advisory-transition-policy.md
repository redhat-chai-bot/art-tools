# Advisory transition attempts

The scheduled advisory-transition scanner processes verified shipment MRs in
any state, excluding RC/EC shipments. It skips any MR labeled
`advisory-transition-success`, `advisory-transition-fail`, or
`advisory-transition-in-progress`. There is no cooldown or automatic retry,
including for temporary service errors or partially completed transitions.

Before enqueueing, the scanner persists `advisory-transition-in-progress` on
the originating MR. It does not enqueue if that write fails. The reservation
survives subsequent scans while Jenkins work is queued or running. Enqueue
errors are recorded as failures when GitLab is available.

The helper passes `SHIPMENT_MR_IID` to Jenkins, which validates it as a positive
integer and passes `--shipment-mr-iid` to `artcd`. The pipeline loads that MR
before loading group configuration. A missing shipment, configuration error,
or a configured MR different from the origin fails the originating attempt;
no advisory commands run on an identity mismatch. All metadata, inspection,
transition, and final-verification errors are terminal. Final verification
runs without Elliott's `--mark`: only after it passes does the pipeline add
success and remove the reservation in one GitLab update. Failure marking
similarly adds fail and removes the reservation without replacing unrelated
labels. Failure marking rechecks success and does not overwrite it. A failed
failure-label write is logged without masking the original exception.

Dry runs perform no label writes or job enqueueing and do not consume attempts.
Pipeline previews still check metadata and inspect advisories; change-state
commands receive `--dry-run` and final hypothetical verification is skipped.

## Serialization and recovery

This protocol relies on the scheduled Jenkins scanner's
`disableConcurrentBuilds()` and the downstream per-version/assembly lock.
Label read/add is not a distributed compare-and-set and does not provide
strict exactly-once execution. Do not run competing scanners outside that
serialization. Direct pipeline invocations also require the originating IID
and the same downstream lock.

To retry a terminal failure, first fix its cause, confirm no old job remains
queued or running, then manually remove `advisory-transition-fail`. There is
no age-based retry. A completed success remains ineligible.

Aborted jobs, skipped locks, Jenkins initialization failures, or an inability
to read the origin or persist a terminal label can leave the reservation in
place. Success-label persistence errors also retain it rather than claiming
success or creating an automatic retry. Inspect Jenkins and the actual
advisory states before recovery; cancel/drain old work first, then manually
record the verified terminal result or remove the stale reservation (and
fail, if present) to authorize another attempt. An ambiguous GitLab response
may already have applied an atomic update: inspect current labels rather
than assuming rollback. Never clear reservations automatically on a timeout.
