#!/usr/bin/env python3
"""Reproduce paper figures from the PUBLIC CID-only dataset (no raw telemetry)."""
from pathlib import Path
from collections import Counter
import json
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.ticker import LogLocator, NullFormatter

ROOT=Path(__file__).resolve().parents[1]
DATA=ROOT/'data/public/ssh_events_cid_only.csv'
OUT=ROOT/'data/derived'
FIG=ROOT/'figures'
OUT.mkdir(parents=True,exist_ok=True)
FIG.mkdir(parents=True,exist_ok=True)

cols=['event_index','session_key','timestamp','endpoint','input_label','event_type','unmatched_category']
df=pd.read_csv(DATA,dtype={'session_key':'string','input_label':'string','timestamp':'string'},low_memory=False)
assert list(df.columns)==cols,df.columns
assert df['endpoint'].eq('HP').all(), 'Endpoint must use one undifferentiated HP label.'
assert df['session_key'].str.fullmatch(r'S\d{6}').all(), 'Malformed session_key.'
assert df['event_type'].isin(['MAPPED_COMMAND','UNMATCHED']).all()
assert (df['event_type'].eq('MAPPED_COMMAND') == df['input_label'].ne('SCAN')).all()

df=df.sort_values(['session_key','timestamp','event_index'],kind='stable')
depth=df.groupby('session_key',sort=True).size().to_numpy()
assert len(depth)==387 and len(df)==378867
mapped=df[df['event_type'].eq('MAPPED_COMMAND')].copy()
mapped['CID']=mapped['input_label'].astype(int)
assert len(mapped)==627
seq={sid:g[['CID','timestamp']].reset_index(drop=True) for sid,g in mapped.groupby('session_key',sort=False)}

summary={
 'session_linked_events':int(len(df)),
 'recorded_sessions':int(len(depth)),
 'mapped_command_events':int(len(mapped)),
 'unmatched_events':int(len(df)-len(mapped)),
 'mapped_command_sessions':int(mapped.session_key.nunique()),
 'unmatched_only_sessions':int(df.session_key.nunique()-mapped.session_key.nunique()),
 'distinct_mapped_CIDs':int(mapped.CID.nunique()),
 'median_recorded_events_per_session':float(np.median(depth)),
 'one_event_sessions':int((depth==1).sum()),
 'at_most_two_events':int((depth<=2).sum()),
 'at_most_five_events':int((depth<=5).sum()),
 'at_most_ten_events':int((depth<=10).sum()),
 'maximum_recorded_events_in_session':int(depth.max()),
 'timestamp_ordering_limit':'One-second timestamp precision',
 'scan_label_limit':'Unmatched records; not necessarily network scanning'
}
(OUT/'reproduced_summary.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf8')

# Recompute unmatched categories from the released, CID-only table.
u=df[df.event_type.eq('UNMATCHED')].groupby('unmatched_category',dropna=False).size().sort_values(ascending=False)
u.rename_axis('unmatched_category').reset_index(name='record_count').to_csv(OUT/'reproduced_unmatched_breakdown.csv',index=False)

# Panel a: empirical CDF of recorded (not command) events per session.
x=np.sort(depth)
y=100*np.arange(1,len(x)+1)/len(x)
fig,ax=plt.subplots(figsize=(6.5,3.8),layout='constrained')
ax.step(np.r_[1,x],np.r_[0,y],where='post',lw=2.2)
for n,off in [(1,(10,6)),(2,(10,8)),(5,(10,9)),(10,(8,8))]:
 pct=100*np.mean(depth<=n)
 ax.scatter(n,pct,s=40,zorder=4)
 ax.annotate(f'{pct:.1f}%',(n,pct),textcoords='offset points',xytext=off,fontsize=9)
ax.set_xscale('log');ax.set_xlim(.8,16000);ax.set_ylim(0,103)
ax.xaxis.set_major_locator(LogLocator(base=10,numticks=7))
ax.xaxis.set_minor_locator(LogLocator(base=10,subs=np.arange(2,10)*.1,numticks=80))
ax.xaxis.set_minor_formatter(NullFormatter())
ax.set_xlabel('Recorded events per session (log scale)')
ax.set_ylabel('Cumulative sessions (%)')
ax.grid(alpha=.2)
fig.savefig(FIG/'fig_empirical_session_depth_verified.png',dpi=220,bbox_inches='tight')
plt.close(fig)

# Panel b: fixed probe groups.  Omit groups without enough qualifying sessions.
probe_df=pd.read_csv(ROOT/'data/public/probe_groups.csv')
rows=[]
for r in probe_df.itertuples():
 group_label=r[1]
 members={int(v.strip()) for v in r[2].split(',')}
 total=0;later=0
 for g in seq.values():
  t0=g.loc[g.CID.isin(members),'timestamp']
  if t0.empty:continue
  total+=1
  if (g['timestamp']>t0.min()).any():later+=1
 if total<10:continue
 rows.append({'category':group_label,'n':total,'continued':later,'not_continued':total-later,'rate':100*later/total})
cont=pd.DataFrame(rows).sort_values('rate',ascending=False,ignore_index=True)
cont.to_csv(OUT/'probe_continuation_counts.csv',index=False)
fig,ax=plt.subplots(figsize=(8.6,4.0),layout='constrained')
pos=np.arange(len(cont))[::-1]
ax.barh(pos,cont['rate'],height=.62,label='Later mapped input')
ax.barh(pos,100-cont['rate'],left=cont['rate'],height=.62,alpha=.32,label='No later mapped input')
ax.set_yticks(pos,cont['category']);ax.set_xlim(0,126)
ax.set_xticks([0,20,40,60,80,100]);ax.set_xlabel('Sessions with later mapped input (%)')
ax.grid(axis='x',alpha=.18);ax.set_axisbelow(True)
for p,r in zip(pos,cont.itertuples()):ax.text(101,p,f'{r.rate:.1f}% ({r.continued}/{r.n})',va='center',fontsize=8.5)
ax.legend(loc='upper center',bbox_to_anchor=(0.50,-0.17),ncol=2,frameon=False,fontsize=8)
fig.savefig(FIG/'fig_probe_continuation_verified.png',dpi=220,bbox_inches='tight')
plt.close(fig)

# Panel c: repeated CID vs strictly timestamp-resolved revalidation.
selected=[(4,'CID 4: sh'),(5,'CID 5: linuxshell'),(1,'CID 1: binary check'),(2,'CID 2: enable'),(3,'CID 3: system')]
rows=[]
for cid,name in selected:
 n=repeated=revalidated=0
 for g in seq.values():
  c=g.CID.to_numpy();t=g.timestamp.to_numpy()
  inds=np.flatnonzero(c==cid)
  if len(inds)==0:continue
  n+=1
  if len(inds)>=2:repeated+=1
  resolved=False
  for i in inds:
   for j in inds:
    if t[i]<t[j] and np.any((t>t[i])&(t<t[j])&(c!=cid)):
     resolved=True;break
   if resolved:break
  revalidated+=int(resolved)
 rows.append({'CID':cid,'label':name,'n':n,'repeated':repeated,'revalidated':revalidated,
              'repeated_pct':100*repeated/n,'strict_pct':100*revalidated/n})
rev=pd.DataFrame(rows)
rev.to_csv(OUT/'cid_revalidation_counts.csv',index=False)
fig,ax=plt.subplots(figsize=(7.4,3.85),layout='constrained')
pos=np.arange(len(rev))[::-1]
ax.barh(pos+.17,rev.repeated_pct,height=.30,label='Repeated CID')
ax.barh(pos-.17,rev.strict_pct,height=.30,label='Resolved revalidation',alpha=.70)
ax.set_yticks(pos,[f'{r.label} (n={r.n})' for r in rev.itertuples()]);ax.set_xlim(0,77)
ax.set_xlabel('Sessions containing the CID (%)');ax.grid(axis='x',alpha=.18);ax.set_axisbelow(True)
for p,r in zip(pos,rev.itertuples()):
 ax.text(r.repeated_pct+.7,p+.17,f'{r.repeated_pct:.1f}% ({r.repeated}/{r.n})',va='center',fontsize=8)
 ax.text(r.strict_pct+.7,p-.17,f'{r.strict_pct:.1f}% ({r.revalidated}/{r.n})',va='center',fontsize=8)
ax.legend(loc='lower right',fontsize=8,frameon=False)
fig.savefig(FIG/'fig_cid_revalidation_verified.png',dpi=220,bbox_inches='tight')
plt.close(fig)

# These assertions intentionally only concern descriptive measurements that are reproducible
# from this privacy-reduced file; no claim about SSH authentication or response causality.
assert summary['median_recorded_events_per_session']==1.0
assert [summary[k] for k in ['one_event_sessions','at_most_two_events','at_most_five_events','at_most_ten_events']]==[230,253,288,311]
assert [(int(r.n),int(r.continued)) for r in cont.itertuples()]==[(50,37),(57,33),(21,6),(15,3),(243,24)]
assert [(int(r.n),int(r.repeated),int(r.revalidated)) for r in rev.itertuples()]==[(44,25,5),(33,13,1),(107,28,2),(14,3,1),(20,3,0)]
print('Verified',json.dumps(summary,indent=2))
print('Reproduced continuation and revalidation tables and 3 figures.')
