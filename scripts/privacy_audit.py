#!/usr/bin/env python3
"""Detect accidental release of direct IPs, indexed HPs, and raw schema fields."""
from pathlib import Path
import csv, re, sys
ROOT=Path(__file__).resolve().parents[1]
INPUT=ROOT/'data/public/ssh_events_cid_only.csv'
EXPECT=['event_index','session_key','timestamp','endpoint','input_label','event_type','unmatched_category']
IP=re.compile(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])')
# Raw source field names are a leakage risk in public CSV/JSON and statistics, not a code/comment.
BAD_ENDPOINT_LABEL=re.compile(r'\bHP[_\-]?\d{1,5}\b',re.I)
BAD_INFRA_COUNT=re.compile(r'(?i)(?:\b(?:number of|total|across|count of)\s+(?:honeypot|collection)\s+(?:endpoints|nodes|ips)\s*[:=]?\s*\d+)|(?:\b\d+\s+(?:honeypot|collection)\s+(?:endpoints|nodes|ips)\b)')
fail=[]
for p in ROOT.rglob('*'):
 if not p.is_file() or '.git' in p.parts:continue
 if p.suffix.lower() in ['.db','.sqlite','.pcap','.pcapng','.pem','.key']:
  fail.append(f'Forbidden file type: {p.relative_to(ROOT)}');continue
 if p.suffix.lower() not in ['.txt','.md','.csv','.json','.tex','.py','.yml','.yaml','.toml','.gitignore'] and p.name not in ['.gitignore','requirements.txt']:
  continue
 text=p.read_text(encoding='utf8')
 if IP.search(text):fail.append(f'IPv4-like literal found: {p.relative_to(ROOT)}')
 if BAD_ENDPOINT_LABEL.search(text):fail.append(f'Indexed endpoint label found: {p.relative_to(ROOT)}')
 if BAD_INFRA_COUNT.search(text):fail.append(f'Potential endpoint count found: {p.relative_to(ROOT)}')
 if p.suffix.lower() in ['.csv','.json','.tex','.md'] and re.search(r'(?i)Sources reaching.*endpoint|Sessions from multi-endpoint sources|honeypot endpoints\s*&',text):
  fail.append(f'Endpoint-count/coverage statement found: {p.relative_to(ROOT)}')
 if p.suffix.lower() in ['.csv','.json','.tex']:
  if re.search(r'\b(?:local_ip|remote_ip|honeypot_id|honeypot_ids|session_id|source_ip)\b',text):
   fail.append(f'Private identifier field found in public artifact: {p.relative_to(ROOT)}')
with INPUT.open(newline='',encoding='utf8') as f:
 r=csv.DictReader(f)
 if r.fieldnames!=EXPECT:fail.append('Dataset schema differs from privacy-reduced public schema.')
 n=0;ses=set();labs=set()
 for row in r:
  n+=1;ses.add(row['session_key']);labs.add(row['endpoint'])
  if row['endpoint']!='HP':fail.append(f'Endpoint disclosure in row {n}');break
  if not re.fullmatch(r'S\d{6}',row['session_key']):fail.append(f'Unredacted session ID in row {n}');break
  if not (row['input_label']=='SCAN' or re.fullmatch(r'\d+',row['input_label'])):
   fail.append(f'Raw command-like input in row {n}');break
 if n!=378867 or len(ses)!=387:fail.append(f'Unexpected released row/session count: {n}/{len(ses)}')
if fail:
 print('PRIVACY AUDIT FAILED:');print('\n'.join(' - '+s for s in fail));sys.exit(1)
print('PASS: No direct IPv4 literals, indexed HP labels, endpoint-count disclosures, raw session IDs or private fields detected in release files.')
print(f'PASS: {n:,} CID-only event rows, {len(ses)} pseudonymous sessions, constant endpoint HP.')
print('NOTE: This automated audit cannot rule out all timestamp-based reidentification risks.')
