# Security and disclosure controls

This public-candidate dataset is explicitly designed to hide **both the IP addresses and the count
of collection endpoints**. All endpoints use the identical `HP` code. No indexed endpoint label is used.

Original source IPs, collection IPs, exact site identifiers, command strings, regex match rules,
payload addresses, credentials, raw session IDs, and any original SQLite database are **excluded**.
The original session IDs can contain address-derived segments; merely retaining or hashing them
unsalted could defeat redaction. New sequential keys are used instead.

Before sharing publicly: run `python scripts/privacy_audit.py`, inspect all files (including
figures and commit history), confirm institutional authorization, and do not publish the parent
folder containing private input files. Prefer creating the GitHub repo from this clean tree, not
from an existing working directory whose commit history may contain raw data.

The audit looks for common accidental disclosures but is not a formal de-identification guarantee;
timestamps and low-frequency behavioral patterns may remain linkable to external information.
