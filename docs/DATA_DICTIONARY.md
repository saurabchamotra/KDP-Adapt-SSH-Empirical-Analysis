# Data dictionary

`data/public/ssh_events_cid_only.csv` contains **only session-linked records**:

| Column | Meaning | Disclosure policy |
| --- | --- | --- |
| `event_index` | Consecutive number assigned to retained rows | Generated afresh; not a raw log ID |
| `session_key` | Arbitrary `S......` code assigned on first encounter | Original session ID discarded; not a cryptographic hash |
| `timestamp` | Original observation time (second resolution; timezone unavailable) | No IP or location encoded |
| `endpoint` | Constant string `HP` for every row | No endpoint-specific codes or counts |
| `input_label` | Numeric CID or `SCAN` | No raw command text |
| `event_type` | `MAPPED_COMMAND` or `UNMATCHED` | Derived from existing labeling |
| `unmatched_category` | Coarse reason for failure to map | Empty for mapped commands |

`data/public/cid_taxonomy.csv` contains only numerical CID and existing tactic/technique metadata.
It does not publish regular expressions, raw strings or private database tables.

`data/public/probe_groups.csv` fixes the descriptive categories used in the figures; these
are research analysis categories, not validated ground-truth attacker intents.

`SCAN` is a **processing label**, not a validated scan detection. Unmatched records may include
control-character payloads, probes, command inputs missing from the rule set, and other material.

Public session keys preserve within-session grouping but not links to the original session IDs;
endpoint-wise and source-IP-wise analyses cannot be recovered from this release by design.
