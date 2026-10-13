# Release verification record

The published candidate was derived from an already classified SSH event CSV. The preprocessing
excluded rows with missing session identifiers and produced 378,867 session-linked event labels.
The private intermediate dataset, source and collection IPs, original session keys, endpoint
identifiers and the raw command-match database **are not included**.

The released `endpoint` field has the same value `HP` in every row. Public session keys were
assigned sequentially and are not substrings or unsalted hashes of raw session identifiers.
Commands are numeric CID labels; `SCAN` means unmatched, not necessarily actual scanning.

| Check | Result |
| --- | --- |
| Released session-linked events | 378,867 |
| Pseudonymous sessions | 387 |
| Mapped command events | 627 |
| Unmatched events | 378,240 |
| Distinct mapped CID codes | 53 |
| Timestamp precision | One second |
| Response-conditioned comparisons possible? | No |
| Original string-to-CID matching publicly reproducible? | No; private rules withheld |
| Endpoint- or source-specific analyses reproducible? | No, by disclosure policy |

`python scripts/privacy_audit.py` checks for raw-looking session keys, dotted IPv4 addresses,
indexed endpoint labels, forbidden raw file formats, and accidental endpoint-coverage claims.
`python scripts/analyze.py` recomputes descriptive measures and asserts the verified count tables.
The privacy test does not guarantee protection against external linkage of timestamp patterns.
Final publication should be authorized and reviewed by the responsible institution.
