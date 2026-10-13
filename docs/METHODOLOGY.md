# Measurement definitions and reproducibility

1. Retain only records with a nonempty original session ID. The remaining event count is the
   **session-linked event count**, not the count of SSH connections, logins or shell commands.
2. Replace each private original session ID with a fresh sequential session key. Preserve the
   grouping relation within each session but never expose the underlying key or IP-derived suffix.
3. Replace all collection endpoints with the single fixed label `HP`.
4. Retain the previously assigned numeric command CID; label unmatched records `SCAN`. All original
   command text, IP fields, match patterns and payload text are excluded.
5. **Event depth** is the number of session-linked records per public session key.
6. **Mapped-input continuation:** among sessions containing at least one mapped CID in a predefined
   group, count sessions with any mapped CID at a timestamp *strictly later* than the first
   group CID's timestamp. A session may occur in multiple groups.
7. **Repeated CID:** CID appears at least twice in a session, even within the same timestamp second.
8. **Timestamp-resolved revalidation:** CID `x` occurs at `t1` and again at `t3` with a different
   mapped CID `y` strictly in between (`t1 < t2 < t3`).
9. Within-second ordering cannot be established from these one-second timestamps. No inference
   of ordering or causality is made where timestamps tie.

## Limitations

- The logging pipeline's emission semantics require separate validation before treating unmatched
  records as scanning behavior or command attempts.
- The public data do not permit recalculation of source-IP or endpoint coverage summaries.
- The original command-to-CID matching rules and raw captured inputs are not distributed.
- The data do not include response-conditioned outcomes and do not establish KDP causal effects.
- Recorded-event depth and experimental executed episode path length (EPL) are different metrics.
- The count of connection/authentication attempts cannot be recovered from these event-level columns.
