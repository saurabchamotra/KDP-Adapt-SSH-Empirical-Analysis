#!/usr/bin/env python3
"""Locally derive public CID-only labels from an already classified PRIVATE intermediate CSV.

Input contains private source, endpoint, and session identifiers. NEVER upload it to GitHub.
No private identifiers are copied to the output. The command regex database is not needed.
"""
import argparse,csv
from pathlib import Path

ap=argparse.ArgumentParser(description=__doc__)
ap.add_argument('--private-input',required=True,type=Path,help='Local private labeled CSV; NEVER commit')
ap.add_argument('--public-output',required=True,type=Path)
args=ap.parse_args()
headers=['event_index','session_key','timestamp','endpoint','input_label','event_type','unmatched_category']
map_s={}
n=0
args.public_output.parent.mkdir(parents=True,exist_ok=True)
with args.private_input.open(newline='',encoding='utf8') as src, args.public_output.open('w',newline='',encoding='utf8') as dest:
 r=csv.DictReader(src)
 missing={'session_id','attack_time','CID','unmatched_indicator'}-set(r.fieldnames or [])
 if missing:raise ValueError(f'Private source missing required columns: {sorted(missing)}')
 w=csv.DictWriter(dest,fieldnames=headers);w.writeheader()
 for event in r:
  sid=event['session_id'].strip()
  if not sid:continue
  if sid not in map_s:map_s[sid]=f'S{len(map_s)+1:06d}'
  n+=1
  cid=event['CID'].strip()
  if cid and not cid.isdigit():raise ValueError('CID field must be numeric or blank')
  w.writerow({'event_index':n,'session_key':map_s[sid],
    'timestamp':event['attack_time'],'endpoint':'HP',
    'input_label':cid or 'SCAN','event_type':'MAPPED_COMMAND' if cid else 'UNMATCHED',
    'unmatched_category':'' if cid else event['unmatched_indicator'].strip()})
print(f'Created a CID-only dataset with {n:,} session-linked rows and pseudonymous session keys.')
print('Remember: do not commit the PRIVATE input file or the private parent directory.')
