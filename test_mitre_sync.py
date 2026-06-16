from analytics.ioc_engine import IOCEngine
import re
import pandas as pd

events = [
    {"timestamp":"2026-06-08T12:00:00","technique":"T1547","mitre_name":"Boot or Logon Autostart Execution","port":3307,"cve":"CVE-2016-6662","service":"mysql","node":"Database","source":"Attacker","detection_confidence":85,"actor":"attacker","message":"sample event 1"},
    {"timestamp":"2026-06-08T12:01:00","technique":"T1595","mitre_name":"Active Scanning","port":8080,"service":"nginx","node":"Webserver","source":"Attacker","detection_confidence":60,"actor":"attacker","message":"sample event 2"},
    {"timestamp":"2026-06-08T12:02:00","technique":"T1190","mitre_name":"Exploit Public-Facing Application","port":5000,"cve":"CVE-2021-23017","service":"dvwa","node":"Firewall / DVWA","source":"Attacker","detection_confidence":92,"actor":"attacker","message":"sample event 3"},
]

ioc_df = IOCEngine.generate_registry_df(events)
print('IOC DF rows:', len(ioc_df))
print(ioc_df[['IOC','Type','Asset','Ports']].to_string(index=False))

# normalize techniques
tech_re = re.compile(r"(T\d{4}(?:\.\d{3})?)", re.IGNORECASE)
ioc_df['_IOC_STR'] = ioc_df['IOC'].astype(str).str.upper()
def extract_base(s):
    m = tech_re.search(s)
    return m.group(1).upper() if m else None
ioc_df['BaseTech'] = ioc_df['_IOC_STR'].apply(extract_base)
tech_rows = ioc_df[ioc_df['BaseTech'].notna()]
print('\nNormalized technique counts:')
print(tech_rows['BaseTech'].value_counts())

# correlation table
rows = []
for tech, cnt in tech_rows['BaseTech'].value_counts().items():
    subset = tech_rows[tech_rows['BaseTech']==tech]
    assets = set()
    if 'Asset' in subset.columns:
        assets.update([a for a in subset['Asset'].astype(str).unique() if a and a!=''])
    if 'Destination' in subset.columns:
        assets.update([d for d in subset['Destination'].astype(str).unique() if d and d!=''])
    ports = set()
    if 'Ports' in subset.columns:
        for pcell in subset['Ports'].astype(str).unique():
            if not pcell or pcell=='':
                continue
            for p in str(pcell).split(','):
                p=p.strip()
                if p:
                    ports.add(p)
    for s in subset['_IOC_STR'].unique():
        for m in re.findall(r'PORT\s*(?:[:=]?\s*)(\d{2,5})', s, flags=re.IGNORECASE):
            ports.add(m)
    try:
        ports_sorted = sorted(ports, key=lambda x: int(x))
    except Exception:
        ports_sorted = sorted(ports)
    rows.append({'Technique':tech,'Count':int(cnt),'Assets Impacted':', '.join(sorted(assets)),'Ports Observed':','.join(ports_sorted)})

corr_df = pd.DataFrame(rows).sort_values('Count',ascending=False).reset_index(drop=True)
print('\nCorrelation table:')
print(corr_df.to_string(index=False))
